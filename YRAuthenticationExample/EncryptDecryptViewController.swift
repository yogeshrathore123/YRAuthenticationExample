//
//  EncryptDecryptViewController.swift
//  YRAuthenticationExample
//
//  Created by Yogesh Rathore on 24/05/19.
//  Copyright © 2019 Yogesh Rathore. All rights reserved.
//

import UIKit

class EncryptDecryptViewController: UIViewController {

    @IBOutlet weak var toEncryptTextField: UITextField!
    @IBOutlet weak var keyToEncryptTextField: UITextField!
    @IBOutlet weak var toDecryptTextField: UITextField!
    @IBOutlet weak var keyToDecryptTextField: UITextField!
    @IBOutlet weak var encyptedDataLabel: UILabel!
    @IBOutlet weak var decryptedDataLabel: UILabel!
    @IBOutlet weak var encryptButton: UIButton!
    @IBOutlet weak var decryptButton: UIButton!
    
    var encryptedData: Data?
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    @IBAction func encryptButtonAction(_ sender: Any) {
        let text = YRSymmetricCryptor().encryptData(text: toEncryptTextField.text ?? "")
        encyptedDataLabel.text = text
        self.view.endEditing(true)
        
    }
    
    @IBAction func decryptButtonAction(_ sender: Any) {
        let decryptedText = YRSymmetricCryptor().decryptData(encryptedString: encyptedDataLabel.text!)
        decryptedDataLabel.text = decryptedText
    }

}
