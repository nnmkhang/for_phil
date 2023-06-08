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



fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

// #[cfg(not(feature = "dangerous_configuration"))]
// fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
//     if args.flag_insecure {
//         panic!("This build does not support --insecure.");
//     }
// }

/// Build a `ClientConfig` from our arguments
fn make_config(ca_file: String) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    let certfile = fs::File::open(ca_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    let num_roots = root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    //root_store.add(ca_);
    println!("{:?}",num_roots);
    println!("{:?}",reader.buffer());

    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store);

    let flag_auth_key = None;
    let flag_auth_certs = None;

    // !!!!!!! THIS PART IS FOR CLIENT AUTH, HAVE TO ENABLE FOR CLIENT AUTH I THE FUTURE 
    let mut config = match (flag_auth_key, flag_auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            println!("in client auth");
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_single_cert(certs, key)
                .expect("invalid client auth certs/key")
        }
        (None, None) =>
        { 
            println!("in no client auth");
            config.with_no_client_auth()
            
        },
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };


    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.enable_tickets = false;
    config.enable_sni = false;

   // config.
    //apply_dangerous_options(args, &mut config);

    Arc::new(config)
}


fn make_capi_config() -> Arc<rustls::ClientConfig> {
    let config = tls_config();
    Arc::new(config)
}


pub struct ClientCertResolver(CertStore, String);

fn get_chain(store: &CertStore, name: &str) -> anyhow::Result<(Vec<Certificate>, CngSigningKey)> {
    let contexts = store.find_by_subject_str(name)?;
//    let context = contexts
//        .first()
//        .ok_or_else(|| anyhow::Error::msg("No client cert"))?;

    let context = contexts.into_iter().find_map(|ctx| {
        if ctx.has_private_key() {
            return Some(ctx);
        }

        None
    }).ok_or_else(|| anyhow::Error::msg("No client cert"))?;

    let key = context.acquire_key()?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context
        .as_chain_der()?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok((chain, signing_key))
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        println!("Server sig schemes: {:#?}", sigschemes);
        let (chain, signing_key) = get_chain(&self.0, &self.1).ok()?;
        for scheme in signing_key.supported_schemes() {
            if sigschemes.contains(scheme) {
                return Some(Arc::new(CertifiedKey {
                    cert: chain,
                    key: Arc::new(signing_key),
                    ocsp: None,
                    sct_list: None,
                }));
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

pub struct ClientCertResolverForServerIssuer(CertStore);
impl ResolvesClientCert for ClientCertResolverForServerIssuer {
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
        for scheme in signing_key.supported_schemes() {
            if sigschemes.contains(scheme) {
                return Some(Arc::new(CertifiedKey {
                    cert: certs,
                    key: Arc::new(signing_key),
                    ocsp: None,
                    sct_list: None,
                }));
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn make_dynamic_cng_config(store_type: CertStoreType, store_name: &str) -> Arc<rustls::ClientConfig> {
    println!("in make_dynamic_cng_config");

    let store = CertStore::open(store_type, store_name).unwrap();
    store.set_auto_resync().unwrap();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_platform())
        .with_client_cert_resolver(Arc::new(ClientCertResolverForServerIssuer(
            store
        )));

    Arc::new(config)
}

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

fn make_capi_with_cng_config() -> Arc<rustls::ClientConfig> {
    println!("in make_capi_with_cng_config");

    let store = CertStore::open(CertStoreType::LocalMachine, "my").unwrap();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_platform())
        .with_client_cert_resolver(Arc::new(ClientCertResolver(
            store,
//            "BadSSL".to_string(),
            "eccplayclient".to_string(),
        )));

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

//    let config:Arc<ClientConfig> = make_config(ca_file);

//    let server_name = "microsoft.com".try_into().unwrap();
//    let server_name = "client.badssl.com".try_into().unwrap();
//    let server_name = "prod.idrix.eu".try_into().unwrap();
//    let server_name = "server.cryptomix.com".try_into().unwrap();
//    let new_config = make_capi_config();
//    let new_config = make_capi_with_cng_config();


    let addr = lookup_ipv4("client.badssl.com", 443);
    let server_name = "client.badssl.com".try_into().unwrap();
//    let new_config = make_dynamic_cng_config(CertStoreType::LocalMachine, "play");

    // For BadSSL Client Certificate
//    let new_config = make_thumbprint_cng_config(CertStoreType::LocalMachine, "play",
//        "d69226ae7828175958fa553c73a92e462a96f783");

    // For eccplayclient
    let new_config = make_thumbprint_cng_config(CertStoreType::LocalMachine, "play",
        "c1737220b3054d83c70228b0beb301deb032992e");
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

