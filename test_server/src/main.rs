use native_tls::{Identity, TlsAcceptor, TlsStream};
use std::fs::File;
use std::io::{Read};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::ffi::OsStr;

//"D:\rust\pfx_leak\test_server\src\playserver_openssl2.pfx"
//"D:\\rust\\pfx_leak\\test_server\\src\\playserver_openssl2.pfx"
fn main(){
    println!("{}", std::env::current_dir().unwrap().display());


    let my_os_str = OsStr::new("user:test:3e2e13a694b3ed9e40849a4ab98b2c84d1b714d8");
    
    // let my_os_str = OsStr::new(r"file:D:\rust\pfx_leak\test_server\test_sst.sst");
    //let my_os_str = OsStr::new(r"file:test\test_sst.sst");


    let unused_pem:[u8; 0] = [];

    let identity = native_tls::Identity::from_os_provider(&unused_pem, OsStr::new("ncrypt"), my_os_str).unwrap();



    // let mut file = File::open("playserver_openssl2.pfx").unwrap();
    // let mut identity = vec![];
    // file.read_to_end(&mut identity).unwrap();
    // let identity = Identity::from_pkcs12(&identity, "openssl").unwrap(); //password is openssl

    let listener = TcpListener::bind("localhost:44330").unwrap();
    dbg!(&listener); //& use ref not move 
    let acceptor = TlsAcceptor::new(identity).unwrap();// idenity drop happens here
    let acceptor = Arc::new(acceptor);
    
    let mut c = 0;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("hit the server");
                if (c == 2)
                {
                    return
                }
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    handle_client(stream);
                });
                c +=1;
            }
            Err(e) => { panic!("{}",e); }
        }
    }

}
fn handle_client(stream: TlsStream<TcpStream>) {
    dbg!(stream);
}

