//
//  MyWrapper.swift
//  MyTLSWrapper
//
//  Created by yarshure on 2018/1/24.
//  Copyright © 2018年 yarshure. All rights reserved.
//

import UIKit
import CocoaAsyncSocket
let timeout:TimeInterval = 10.0
import Security
class MyWrapper: NSObject,GCDAsyncSocketDelegate {

    var socket:GCDAsyncSocket!
    var ctx:SSLContext!
    var certState:SSLClientCertificateState!
    var negCipher:SSLCipherSuite!
    var negVersion:SSLProtocol!
    let handShakeTag:Int = -3000
    var handShanked:Bool = false
    var queue:DispatchQueue = DispatchQueue.init(label: "tls.dispatch.quque")
    var remoteAddress:String!
    var readBuffer:Data = Data() //recv from socket
    var writeBuffer:Data = Data() //prepare write to  socket
    public let tempq = DispatchQueue.init(label: "tls.queue")
    
    func test(_ msg:String){
        print(msg)
    }
    override init() {
       
        super.init()
         socket = GCDAsyncSocket.init(delegate: self, delegateQueue: self.queue)
    }
    func connectTo(_ remote:String ,port:UInt16) {
        self.remoteAddress = remote
        do {
            try socket.connect(toHost: remote, onPort: port)
        }catch let e {
            print(e.localizedDescription)
        }
        
    }
    internal  func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        print("didDisconnectWith")
    }
   
    func checkStatus(status:OSStatus) {
        if status != 0{

            print(status)
        }
    }
    func showState() ->SSLSessionState  {
        var state:SSLSessionState = SSLSessionState.init(rawValue: 0)!
        SSLGetSessionState(ctx, &state)
        print("SSLHandshake...state:" + state.description)
        return state
        
    }
    internal func socket(_ sock: GCDAsyncSocket, didConnectToHost host: String, port: UInt16) {
        print("didConnectWith")
        
        if !handShanked{
            tempq.async {
                self.configTLS()
            }
        }
      
    }
 
    func check(_ status:OSStatus) {
        if status != 0{
            print("print \(status)")
        }
    }
    open func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
    
        print("socket didRead count:\(data.count)")
        //handshake auto read/write
        if handShanked {
            tempq.suspend()
            self.readBuffer.append(data)
            tempq.resume()
            
            
            tlsRead()
        }else {
            tempq.suspend()
            self.readBuffer.append(data)
            tempq.resume()
            
        }
        socket.readData(withTimeout: timeout, tag: handShakeTag)
    }
    func tlspending() ->Int{
        var result:UnsafeMutablePointer<Int> = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        defer {
            result.deallocate(capacity: 1)
        }
        
        if (SSLGetBufferedReadSize(ctx, result) < 0) {
            return 0;
        }
        
        return result.pointee;
    }
    func tlsRead() {

            var status:OSStatus
            repeat {
                var result:UnsafeMutablePointer<Int> = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                defer {
                    result.deallocate(capacity: 1)
                }
               
                
                let  buff:UnsafeMutableRawPointer = UnsafeMutableRawPointer.allocate(bytes: 4096, alignedTo: 1)
                status = SSLRead(self.ctx, buff , 4096,   result)
                self.checkStatus(status: status)
                if result.pointee > 0 {
                    //print("TLS didRead \(buffer as NSData) count:\(result.pointee )")
                    //buffer.count = result.pointee
                    let responseDatagram = NSData(bytes: buff, length: result.pointee)
                    print("ssl read count\(result.pointee) \(responseDatagram)")
                }else {
                    print("ssl read no data,continue read")
                    
                }
            }while (status != errSSLWouldBlock)


        
    }
    open func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int)  {
        
        
        if !handShanked {
            print("didwrite reading...")
        }else {
            print("didwrite reading... \(tag)")
        }
        socket.readData(withTimeout: timeout, tag: handShakeTag)
    }
    
    func readFunc() ->SSLReadFunc {
        return { c,data,len in
            print("ReadFunc...need length:\(len.pointee)" )
           
            let unmanaged:Unmanaged<MyWrapper>  =   Unmanaged.fromOpaque(c)
            let socketfd:MyWrapper = unmanaged.takeUnretainedValue()
            
            let bytesRequested = len.pointee
            
            // Read the data from the socket...
            if socketfd.readBuffer.isEmpty {
                print("readFunc no data")
                len.initialize(to: 0)
                return OSStatus(errSSLWouldBlock)
            }else {
                //
                var toRead:Int = 0
                if socketfd.readBuffer.count >= bytesRequested {
                    toRead = bytesRequested
                }else {
                    toRead = socketfd.readBuffer.count
                    
                }
               
                memcpy(data, (socketfd.readBuffer as NSData).bytes,toRead)
                socketfd.readBuffer.removeSubrange( 0..<toRead)
                print("readbuffer left:\(socketfd.readBuffer.count)")
               
                len.initialize(to: toRead)
                
                if bytesRequested > toRead {
                    
                    return OSStatus(errSSLWouldBlock)
                    
                } else {
                    
                    return noErr
                }
            }
        }
    }
    func writeFunc() ->SSLWriteFunc {
        return { c,data,len in
            //let con:MyWrapper = c.assumingMemoryBound(to: MyWrapper.self).pointee
            let unmanaged:Unmanaged<MyWrapper>  =   Unmanaged.fromOpaque(c)
            let con:MyWrapper = unmanaged.takeUnretainedValue()
            print("writeFunc...")
            
          
            let responseDatagram = NSData(bytes: data, length: len.pointee)
            con.writeRawData(responseDatagram as Data, tag: 0)
           
            return 0
            
        }
    }
    public func configTLS(){
        
       
        ctx = SSLCreateContext(kCFAllocatorDefault, .clientSide, .streamType)
        var status: OSStatus
       
     
        status = SSLSetIOFuncs(ctx, readFunc(), writeFunc())
        
        checkStatus(status: status)
        
        //SSLSetConnection(ctx, UnsafePointer(.toOpaque()))
        let connect = Unmanaged.passUnretained(self).toOpaque()
        status = SSLSetConnection(ctx, connect)
        checkStatus(status: status)
        status = SSLSetPeerDomainName(ctx, remoteAddress, remoteAddress.count)
        //status = SSLSetSessionOption(ctx, SSLSessionOption.breakOnClientAuth, true)
        checkStatus(status: status)
        status = SSLSetProtocolVersionMin(ctx, SSLProtocol.tlsProtocol1)
        status = SSLSetProtocolVersionMax(ctx, SSLProtocol.tlsProtocol13)
        var numSupported:Int = 0
        status = SSLGetNumberEnabledCiphers(ctx, &numSupported)
        print("enabled ciphers count \(numSupported)")
        checkStatus(status: status)
      
        status = SSLSetSessionOption(ctx, SSLSessionOption.breakOnClientAuth, true)
        checkStatus(status: status)
        print("begin SSLHandshake...")
        repeat {
            status = SSLHandshake(self.ctx);
            
            checkStatus(status: status)
           
            
            usleep(500)
        }while(status == errSSLWouldBlock)
        
        //Handshake complete, ready for normal I/O
        if showState() == .connected {
            self.handShanked = true
            let cert:UnsafeMutablePointer<SSLClientCertificateState> = UnsafeMutablePointer<SSLClientCertificateState>.allocate(capacity: 1)
            defer {
                cert.deallocate(capacity: 1)
            }
            
            status = SSLGetClientCertificateState(ctx, cert)
            checkStatus(status: status)
           
            var t:SecTrust?
            status =  SSLCopyPeerTrust(ctx, &t)
            checkStatus(status: status)

            let req =     "GET / HTTP/1.1\r\nHost: www.apple.com\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n".data(using: .utf8)!
            self.writeData(req, withTag: 0)
            print("SSLHandshake...Finished  OK")
        }else {
           print("SSLHandshake...Finished  failure")
        }
        
        
        
    }
    
     public func writeData(_ data: Data, withTag: Int) {
        //call TLS write
       
        var result:UnsafeMutablePointer<Int> = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        defer {
            result.deallocate(capacity: 1)
        }
        SSLWrite(self.ctx, (data as NSData).bytes, data.count,result )
        print(result.pointee)
        
    }
    
    ///for TLS
    
    func writeRawData(_ data:Data, tag:Int){
      
        socket.write(data, withTimeout: 10, tag: 0)
    }
    
    deinit {
        SSLClose(ctx)
    }

}
