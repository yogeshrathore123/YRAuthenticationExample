//
//  ViewController.swift
//  YRAuthenticationExample
//
//  Created by Yogesh Rathore on 24/05/19.
//  Copyright © 2019 Yogesh Rathore. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    @IBAction func loginBtn(_ sender: Any) {
        YRBiometricHelper().authenticateUser(policy: AuthenticationPolicy.deviceOwnerAuth) { (authenticationStatus, title, msg) in
            if authenticationStatus ==  BiometricAuthenticationStatus.Success {
//                self.pushController(identifier: "DateTimePickerViewController")
                self.notifyUser("Congratulations", message: "Login Successfull")
            }
            else{
                self.notifyUser(title, message: msg)
            }
        }
    }
    
    @IBAction func EncrytExamplaeBtn(_ sender: Any) {
        self.pushController(identifier: "EncryptDecryptViewController")
    }
    
    func notifyUser(_ title: String, message: String?) {
        let alert = UIAlertController(title: title, message: message ?? "", preferredStyle: .alert)
        let cancelAction = UIAlertAction(title: "OK",
                                         style: .cancel, handler: {
                                            action in
                                                    })
        alert.addAction(cancelAction)
        self.present(alert, animated: true,
                     completion: nil)
    }
    

}


extension UIViewController
{
    func pushController(identifier : String)
    {
        if let nextViewController = storyboard?.instantiateViewController(withIdentifier: identifier) {
            self.navigationController?.pushViewController(nextViewController, animated: true)
        }
    }
}

