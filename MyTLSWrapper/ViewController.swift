//
//  ViewController.swift
//  MyTLSWrapper
//
//  Created by yarshure on 2018/1/24.
//  Copyright © 2018年 yarshure. All rights reserved.
//

import UIKit
import CocoaAsyncSocket
class ViewController: UIViewController {

    let tlsWrapper:MyWrapper = MyWrapper()
    override func viewDidLoad() {
        super.viewDidLoad()
     
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    @IBAction func startConnect(_ sender: Any) {
        tlsWrapper.connectTo("www.apple.com", port: 443)
    }
    

}

