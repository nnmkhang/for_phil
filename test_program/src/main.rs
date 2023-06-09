use std::process;
use std::sync::Arc;

use mio::net::TcpStream;

use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::str;
use rustls::{OwnedTrustAnchor, RootCertStore};
use rustls::ServerName;

use rustls_platform_verifier::tls_config;
use rustls_platform_verifier::verifier_for_platform;
// use rustls::ClientConfig;
const CLIENT: mio::Token = mio::Token(0);

use rustls::{
    client::ResolvesClientCert, sign::CertifiedKey, Certificate, ClientConfig, ClientConnection,
    sign::SigningKey,
    SignatureScheme, Stream,
};

use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
    cert::{CertChainEngineType, CertAiaRetrievalType},
};

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, source: &str) -> io::Result<usize> {
        let buf = source.as_bytes();
        self.tls_conn.writer().write_all(buf)?;
        Ok(buf.len())
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn
                .reader()
                .read_exact(&mut plaintext)
                .unwrap();
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}


// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}



// Use rustls-platform-verifier to verify server certificate
// No client certificates
fn make_capi_config() -> Arc<rustls::ClientConfig> {
    let config = tls_config();
    Arc::new(config)
}



// Resolver for make_issuer_name_list_cng_config
//
// The certificate and key are found and created dynamically for each
// TLS connection.
//
// Since the certificate chain is built during the connection only allow
// CacheOnly AIA retrieval.
pub struct ClientCertResolverForIssuerNameList(CertStore);
impl ResolvesClientCert for ClientCertResolverForIssuerNameList {
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let context = self.0.find_client_cert(acceptable_issuers).ok()?;

        let key = context.acquire_key().ok()?;
        let signing_key = CngSigningKey::new(key).ok()?;

        println!("Key alg group: {:?}", signing_key.key().algorithm_group());
        println!("Key alg: {:?}", signing_key.key().algorithm());

        // attempt to acquire a full certificate chain
        let chain_engine_type;
        if self.0.is_local_machine() {
            chain_engine_type = CertChainEngineType::LocalMachine;
        } else {
            chain_engine_type = CertChainEngineType::CurrentUser;
        }

        let chain = context.as_chain_der_ex(
                        chain_engine_type,
                        CertAiaRetrievalType::CacheOnly,
                        false,                              // include_root
                        Some(self.0.clone())
                     ).ok()?;
        let certs = chain.into_iter().map(Certificate).collect();

        println!("Server sig schemes: {:#?}", sigschemes);
        if signing_key.choose_scheme(sigschemes).is_some() {
            return Some(Arc::new(CertifiedKey {
                cert: certs,
                key: Arc::new(signing_key),
                ocsp: None,
                sct_list: None,
            }));
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// Use rustls-platform-verifier to verify server certificate
//
// Use rustls-cng to provide the client cert via the server's provided
// Issuer Name List

// Note, the rustls-platform-verifier crate MUST BE UPDATED to include the following:
//  In src\lib.rs add the following after pub fn tls_config()

//  /// Exposed so application can provide a client_cert_resolver
//  pub fn verifier_for_platform() -> Arc<dyn rustls::client::ServerCertVerifier> {
//      Arc::new(Verifier::new())
//  }

fn make_issuer_name_list_cng_config(store_type: CertStoreType, store_name: &str) -> Arc<rustls::ClientConfig> {
    println!("in make_issuer_name_list_cng_config");

    let store = CertStore::open(store_type, store_name).unwrap();
    store.set_auto_resync().unwrap();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_platform())
        .with_client_cert_resolver(Arc::new(ClientCertResolverForIssuerNameList(
            store
        )));

    Arc::new(config)
}

// Resolver for:
//   make_issuer_name_list_cng_config
//   make_by_name_cng_config
//
// The certificate and key were found and created during make config
pub struct CacheClientCertResolver(Arc<CertifiedKey>);
impl ResolvesClientCert for CacheClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        println!("in resolve for CacheClientCertResolver");

        let signing_key = &self.0.key;
        println!("Key alg: {:?}", signing_key.algorithm());

        println!("Server sig schemes: {:#?}", sigschemes);
        if signing_key.choose_scheme(sigschemes).is_some() {
            return Some(Arc::clone(&self.0));
        } 

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// Use rustls-platform-verifier to verify server certificate
//
// See above for how the rustls-platform-verifier crate MUST BE UPDATED.
//
// Use rustls-cng to provide the client cert by finding by sha1 or
// sha1+sha256 thumbprint. Chases down renewed certificates via the
// CERT_RENEWAL_PROP_ID property.
//
// Since the certificate chain is built during make config we can do
// Network AIA retrieval.

fn make_thumbprint_cng_config(store_type: CertStoreType, store_name: &str,
                              hex_thumbprint: &str) -> Arc<rustls::ClientConfig> {
    println!("in make_thumbprint_cng");


    let store = CertStore::open_for_sha1_find(store_type, store_name).unwrap();
    let thumbprint = hex::decode(hex_thumbprint).unwrap();
    let context = store.find_last_renewed(&thumbprint).unwrap();

    let key = context.acquire_key().unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();

    let chain_engine_type = match store_type {
        CertStoreType::LocalMachine => CertChainEngineType::LocalMachine,
        _ => CertChainEngineType::CurrentUser,
    };

    let chain = context
        .as_chain_der_ex(
            chain_engine_type,
            CertAiaRetrievalType::Network,
            false,              // include_root
            None).unwrap()      // additional_store
        .into_iter()
        .map(Certificate)
        .collect();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_platform())
        .with_client_cert_resolver(Arc::new(CacheClientCertResolver(
            Arc::new(CertifiedKey {
                cert: chain,
                key: Arc::new(signing_key),
                ocsp: None,
                sct_list: None,
            }))));

    Arc::new(config)
}

// Use rustls-platform-verifier to verify server certificate
//
// See above for how the rustls-platform-verifier crate MUST BE UPDATED.
//
// Use rustls-cng to provide the client cert by finding by subject name substring
//
// Since the certificate chain is built during make config we can do
// Network AIA retrieval.
fn make_by_name_cng_config(store_type: CertStoreType, store_name: &str,
                              name: &str) -> Arc<rustls::ClientConfig> {
    println!("in make_by_namethumbprint_cng");


    let store = CertStore::open(store_type, store_name).unwrap();
    let contexts = store.find_by_subject_str(name).unwrap();
//    let contexts = store.find_by_issuer_str(name).unwrap();
    let context = contexts.into_iter().find_map(|ctx| {
        if ctx.has_private_key() && ctx.is_time_valid() {
            return Some(ctx);
        }

        None
    }).unwrap();

    let key = context.acquire_key().unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();

    let chain_engine_type = match store_type {
        CertStoreType::LocalMachine => CertChainEngineType::LocalMachine,
        _ => CertChainEngineType::CurrentUser,
    };

    let chain = context
        .as_chain_der_ex(
            chain_engine_type,
            CertAiaRetrievalType::Network,
            false,              // include_root
            Some(store)).unwrap()      // additional_store
        .into_iter()
        .map(Certificate)
        .collect();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_platform())
        .with_client_cert_resolver(Arc::new(CacheClientCertResolver(
            Arc::new(CertifiedKey {
                cert: chain,
                key: Arc::new(signing_key),
                ocsp: None,
                sct_list: None,
            }))));

    Arc::new(config)
}


/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    println!("{}", version);
    env_logger::Builder::new()
    .parse_filters("trace")
    .init();
    

    // VARIABLES FOR THE RUN:
    let ca_file = String::from("root.pem");
//    let addr = lookup_ipv4("microsoft.com", 443);
//    let addr = lookup_ipv4("client.badssl.com", 443);
//    let addr = lookup_ipv4("prod.idrix.eu", 443);
//    let addr = lookup_ipv4("server.cryptomix.com", 443);

//    let server_name = "microsoft.com".try_into().unwrap();
//    let server_name = "client.badssl.com".try_into().unwrap();
//    let server_name = "prod.idrix.eu".try_into().unwrap();
//    let server_name = "server.cryptomix.com".try_into().unwrap();
//    let new_config = make_capi_config();


//    let addr = lookup_ipv4("client.badssl.com", 443);
//    let server_name = "client.badssl.com".try_into().unwrap();
    let new_config = make_issuer_name_list_cng_config(CertStoreType::LocalMachine, "play");

    // For BadSSL Client Certificate
//    let new_config = make_thumbprint_cng_config(CertStoreType::LocalMachine, "play",
//        "d69226ae7828175958fa553c73a92e462a96f783");


    // For eccplayclient
    let addr = lookup_ipv4("prod.idrix.eu", 443);
    let server_name = "prod.idrix.eu".try_into().unwrap();
    let new_config = make_thumbprint_cng_config(CertStoreType::LocalMachine, "play",
        "c1737220b3054d83c70228b0beb301deb032992e");

    let new_config = make_by_name_cng_config(CertStoreType::LocalMachine, "play",
        "eccplayclient");

    let mut sock = TcpStream::connect(addr).unwrap();
    let mut tlsclient = TlsClient::new(sock, server_name, new_config);


 
    // let httpreq = format!(
    //     "GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
    //                         close\r\nAccept-Encoding: identity\r\n\r\n",
    //     "microsoft.com"
    // );
    // tlsclient
    //     .write_all(httpreq.as_bytes())
    //     .unwrap();

    let mut message = "helloworld";
        tlsclient
            .read_source_to_end(&mut message) // make reader based on string, so you dont have to | echo hello world so that we can debug
            .unwrap();


    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(poll.registry());

    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            tlsclient.ready(ev);
            tlsclient.reregister(poll.registry());
        }
    }
}

