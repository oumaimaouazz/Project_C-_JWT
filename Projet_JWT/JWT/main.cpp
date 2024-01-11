#include "mainwindow.h"
#include <QApplication>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QComboBox>
#include <QPushButton>
#include <QTextEdit>
#include <QGridLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QJsonObject>
#include <QJsonDocument>
#include <QByteArray>
#include <QMessageBox>
#include <QTextCursor>
#include <QFrame>
#include <QCheckBox>
#include<openssl/ssl.h>
#include<openssl/crypto.h>
#include<QCryptographicHash>
#include <QCoreApplication>
#include <QMessageAuthenticationCode>
#include <openssl/err.h>
#include<QJsonDocument>
#include<QDebug>
#include <QScrollArea>

class Window : public QWidget {
public:
    Window(QWidget* parent = nullptr) : QWidget(parent) {
        setWindowTitle("JWT");
        setGeometry(0, 0, 500, 500);



        mainlayout = new QVBoxLayout();
        setLayout(mainlayout);

        group1 = new QGroupBox();
        formlayout = new QFormLayout();
        group1->setLayout(formlayout);
        mainlayout->addWidget(group1);

        vecbox = new QGridLayout();
        mainlayout->addLayout(vecbox);
        vecbox1 = new QVBoxLayout();
        vecbox2 = new QVBoxLayout();
        vecbox4 = new QVBoxLayout();
        vecbox5 = new QVBoxLayout();

        vecbox3 = new QVBoxLayout();
        vecbox->addLayout(vecbox3, 2, 0);
        vecbox->addLayout(vecbox1, 0, 0);
        vecbox->addLayout(vecbox2, 1, 0);
        vecbox->addLayout(vecbox5, 2, 0);

        vecbox->addLayout(vecbox4, 0, 1, 4, 1);

        group3 = new QGroupBox();
        hlayout1 = new QHBoxLayout();
        group3->setLayout(hlayout1);
        mainlayout->addWidget(group3);

        label_algorithme = new QLabel("Algorithme :");
        label_algorithme->setStyleSheet("font: bold 13px; font-family: Arial; background-color: white;");


        label_text = new QLabel("coded :");
        label_text->setStyleSheet("font: bold 13px; font-family: Arial;");
        label_token = new QLabel("TOKEN :");
        label_token->setStyleSheet("font: bold 11px; font-family: Arial;");
        label_hedear = new QLabel("HEADER: ALGORITHM & TOKEN TYPE");
        label_hedear->setStyleSheet("font: bold 11px ; font-family: Arial;");
        label_paylood = new QLabel("PAYLOAD: DATA");
        label_paylood->setStyleSheet("font: bold 11px; font-family: Arial;");
        label_verify = new QLabel("VERIFY SIGNATURE:");
        label_verify->setStyleSheet("font: bold 11px; font-family: Arial;");
        label_decoded = new QLabel("decoded");
        label_decoded->setStyleSheet("font: bold 13px; font-family: Arial;");

        label_verification = new QLabel();
        label_verification->setText("Signature Verified");
        label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");

        codageButton = new QPushButton("coding");
        decodageButton = new QPushButton("decoding");

        deleteButton = new QPushButton("delete");
        comboBox_Algrithme = new QComboBox();
        comboBox_Algrithme->addItem("HS256");
        comboBox_Algrithme->addItem("HS384");
        comboBox_Algrithme->addItem("HS512");
        comboBox_Algrithme->addItem("RS256");
        comboBox_Algrithme->addItem("RS384");
        comboBox_Algrithme->addItem("RS512");

        comboBox_Algrithme->setMaximumSize(200,30);


        token_textedit = new QTextEdit();



        // Ajoutez votre QTextEdit à votre layout ou à un conteneur approprié
        // par exemple, si vous utilisez mainlayout:
        mainlayout->addWidget(token_textedit);
        header_textedit = new QTextEdit();
        paylood_textedit = new QTextEdit();

        updateHeaderText();
        updatePayloodText();

        formlayout->addRow(label_algorithme, comboBox_Algrithme);

        vecbox1->addWidget(label_text);
        vecbox1->addWidget(label_hedear);
        vecbox1->addWidget(header_textedit);
        vecbox2->addWidget(label_paylood);
        vecbox2->addWidget(paylood_textedit);

        vecbox5->addWidget(label_verify);

        vecbox4->addWidget(label_decoded);
        vecbox4->addWidget(label_token);
        vecbox4->addWidget(token_textedit);

        hlayout1->addWidget(label_verification);
        hlayout1->addSpacing(100);
        hlayout1->addWidget(codageButton);
        hlayout1->addWidget(deleteButton);

        hlayout1->addWidget(decodageButton);
        //hlayout1->addWidget(validationButton);
        connect(comboBox_Algrithme, &QComboBox::currentTextChanged, this, &Window::updateHeaderText);
        connect(codageButton, &QPushButton::clicked, this, &Window::encode);
        connect(codageButton, &QPushButton::clicked, this, &Window::encodePayload);
        connect(codageButton, &QPushButton::clicked, this, &Window::appel);
        // connect(codageButton, &QPushButton::clicked, this, &Window::coded_HMACSHA384);
        connect(comboBox_Algrithme, &QComboBox::currentTextChanged, this, &Window::updateS);
        connect(deleteButton, &QPushButton::clicked, this, &Window::deleteTokenText);
        connect(comboBox_Algrithme, &QComboBox::currentTextChanged, this, &Window::updatePayloodText);
        //connect(validationButton, &QPushButton::clicked, this, &Window::validate_RSASHA);

        connect(header_textedit, &QTextEdit::textChanged, this, &Window::verifySignature);
        connect(paylood_textedit, &QTextEdit::textChanged, this, &Window::verifySignature);
        connect(token_textedit , &QTextEdit::textChanged, this, &Window::validate_RSASHA);

        connect(decodageButton, &QPushButton::clicked, this, &Window::decode);
        connect(token_textedit, &QTextEdit::textChanged, this, &Window::colors);

        frame = nullptr;
        label_sign = nullptr;
        verify_textedit = nullptr;
        textedit_pravite = nullptr;
        textedit_public = nullptr;
        checkbox_base64 = nullptr;
    }

public slots:

    void colors() {
        // Déconnectez temporairement le signal pour éviter une boucle infinie
        disconnect(token_textedit, &QTextEdit::textChanged, this, &Window::colors);

        QString Token = token_textedit->toPlainText();

        // Vérifiez si le QTextEdit est vide
        if (Token.isEmpty()) {
            token_textedit->setPlainText(Token);
        } else {
            QStringList tokenParts = Token.split('.');
            if (tokenParts.size() == 3) {
                QString firstPart = tokenParts.value(0);
                QString secondPart = tokenParts.value(1);
                QString thirdPart = tokenParts.value(2);

                // Concaténez les parties colorées avec des balises de couleur HTML
                QString coloredText = "<font color='red'><b style='font-size:16px;'>" + firstPart + "</b></font>."
                                                                                                    "<font color='#D63AFF'><b style='font-size:16px;'>" + secondPart + "</b></font>."
                                                     "<font color='#00B9F1'><b style='font-size:16px;'>" + thirdPart + "</b></font>";


                // Affichez le texte coloré dans votre QTextEdit
                token_textedit->setHtml(coloredText);
            } else {
                // Affichez simplement le texte brut dans le QTextEdit si le token n'a pas trois parties
                token_textedit->setPlainText(Token);
            }
        }

        // Reconnectez le signal après la modification
        connect(token_textedit, &QTextEdit::textChanged, this, &Window::colors);
    }


    void update_sig(){
        QString Algorithme = comboBox_Algrithme->currentText();
        if (Algorithme == "HS256"||Algorithme == "HS512"||Algorithme == "HS384"){
            QString corrantkey=verify_textedit->toPlainText();
            updateS();
            verify_textedit->setPlainText(corrantkey);}
        else if(Algorithme == "RS256"||Algorithme == "RS512"||Algorithme == "RS384"){
            QString privatekey=textedit_pravite->toPlainText();
            QString publickey=textedit_public->toPlainText();
            updateS();
            textedit_pravite->setPlainText(privatekey);
            textedit_public->setPlainText(publickey);
        }else{
            updateS();
        }

    }





    // Méthode pour charger la clé privée RSA à partir de la chaîne de texte
    RSA* loadPrivateKeyFromString(const QString& privateKeyString) {
        BIO* privateKeyBio = BIO_new_mem_buf(privateKeyString.toUtf8().constData(), -1);
        if (!privateKeyBio) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            //return nullptr;
        }

        RSA* privateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
        BIO_free(privateKeyBio);

        if (!privateKey) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            //ERR_print_errors_fp(stderr); // Afficher les erreurs OpenSSL
            //return nullptr;
        }

        return privateKey;
    }

    // Méthode pour charger la clé public RSA à partir de la chaîne de texte


    RSA* loadPublicKeyFromString(const QString& publicKeyString) {
        BIO* publicKeyBio = BIO_new_mem_buf(publicKeyString.toUtf8().constData(), -1);
        if (!publicKeyBio) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            //return nullptr;
        }

        RSA* publicKey = PEM_read_bio_RSA_PUBKEY(publicKeyBio, NULL, NULL, NULL);
        BIO_free(publicKeyBio);

        if (!publicKey) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");

            //ERR_print_errors_fp(stderr); // Afficher les erreurs OpenSSL
            //return nullptr;
        }

        return publicKey;
    }










    QByteArray removeLineEndings(const QByteArray &input) {
        QByteArray output;
        for (char ch : input) {
            if (ch != '\n' && ch != '\r') {
                output.append(ch);
            }
        }
        return output;
    }
    void updateS(){
        QString Algorithme = comboBox_Algrithme->currentText();
        QString name_algorithme;
        if (Algorithme == "HS256") {
            name_algorithme = "HMACSHA256";

        } else if (Algorithme == "HS384") {
            name_algorithme = "HMACSHA384";
        }
        else if (Algorithme == "HS512"){
            name_algorithme = "HMACSHA512";
        }
        else if (Algorithme == "RS256") {
            name_algorithme = "RSASHA256";
        }
        else if (Algorithme == "RS384") {
            name_algorithme = "RSASHA384";
        }
        else if (Algorithme == "RS512") {
            name_algorithme = "RSASHA512";
        }
        else if (Algorithme == "PS256") {
            name_algorithme = "RSAPSSSHA256";
        }
        else if (Algorithme == "ES265") {
            name_algorithme = "ECDSASHA256";
        }

        if (frame) {
            delete frame;
            frame = nullptr;
        }

        frame = new QFrame();
        frame->setFrameStyle(QFrame::Box);
        vecbox3 = new QVBoxLayout();
        frame->setLayout(vecbox3);
        vecbox->addWidget(frame, 3, 0);

        label_sign = new QLabel();
        label_sign->setStyleSheet("font: 11px; font-family: Arial;");
        QLabel* label_key = new QLabel("secret key");

        label_key->setStyleSheet("font:bold 11px; font-family: Arial;");
        label_key->setStyleSheet("color: #00B9F1;");
        vecbox3->addWidget(label_sign);
        vecbox3->addWidget(label_key);

        if (name_algorithme == "HMACSHA384" || name_algorithme == "HMACSHA256"||name_algorithme =="HMACSHA512") {
            verify_textedit = new QTextEdit();
            verify_textedit->setFixedHeight(30);
            verify_textedit->setFixedWidth(200);
            verify_textedit->setText("my_secret_key_123!@#");
            verify_textedit->setStyleSheet("color: #00B9F1;");
            label_parenthese = new QLabel(")");
            label_parenthese->setStyleSheet("color: #00B9F1;");
            label_parenthese->setStyleSheet("font:13px; font-family: Arial;");
            checkbox_base64 = new QCheckBox("Base64 Encoded");
            checkbox_base64->setStyleSheet("color: #00B9F1;");
            vecbox3->addWidget(verify_textedit);
            vecbox3->addWidget(label_parenthese);
            vecbox3->addWidget(checkbox_base64);



        } else {
            textedit_pravite =new QTextEdit();
            textedit_pravite->setPlaceholderText("Private Key in PKCS #8, PKCS # 1, or JWK string format. The k ey never leaves your browser.");

            textedit_public = new QTextEdit();
            textedit_public->setPlaceholderText("Public Key in SPKI, PKCS #1, X.509 Certificate, or JWK string format.");

            label_parenthese2 = new QLabel(")");
            label_parenthese2->setStyleSheet("font:13px; font-family: Arial;");
            label_parenthese2->setStyleSheet("color: #00B9F1;");
            vecbox3->addWidget(textedit_pravite);
            vecbox3->addWidget(textedit_public);
            vecbox3->addWidget(label_parenthese2);
        }

        QString newname = QString("%1\(\nbase64UrlEncode(header) + \".\" +\nbase64UrlEncode(payload)),").arg(name_algorithme);
        label_sign->setStyleSheet("color: #00B9F1;");
        label_sign->setText(newname);
    }


    // hs256 / hs384 / HS512


    void appel(){
        QString Algorithme = comboBox_Algrithme->currentText();
        if (Algorithme == "HS256"  ) {
            coded_HMACSHA256();
        }
        else if(Algorithme == "HS384" ){
            coded_HMACSHA384();
        }
        else if(Algorithme == "HS512" ){
            coded_HMACSHA512();
        }
        else if(Algorithme == "RS256" ){
            coded_RSASHA256();
        }
        else if(Algorithme == "RS384" ){
            coded_RSASHA384();
        }
        else if(Algorithme == "RS512" ){
            coded_RSASHA512();
        }


        else{
            QMessageBox::critical(this, "Erreur JSON", "HS256");
            return;
        }
    }
    //******************************************************************************************
    void validate_RSASHA(){
        QString Algorithme = comboBox_Algrithme->currentText();
        if(Algorithme == "RS256" ){
            validate_RSASHA256();

        }
        else if(Algorithme == "RS384" ){
            validate_RSASHA384();


        }
        else if(Algorithme == "RS512" ){
            validate_RSASHA512();
        }
        else{
            QStringList parts = token_textedit->toPlainText().split('.');
            QString secretKey= verify_textedit->toPlainText();
            if (parts.size() == 3) {
                QByteArray encodedHeader = parts[0].toUtf8();
                QByteArray encodedPayload = parts[1].toUtf8();
                QByteArray signature = parts[2].toUtf8();

                // Decode the payload (Base64 decoding)
                //QByteArray decodedPayload = QByteArray::fromBase64(QByteArray::fromPercentEncoding(encodedPayload));

                // Verify the signature using HMACSHA256
                QByteArray dataToSign;
                QByteArray expectedSignature;
                dataToSign=encodedHeader + "." + encodedPayload;

                if (Algorithme == "HS256"  ) {
                    if (checkbox_base64->isChecked()) {
                        secretKey = QString::fromUtf8(base64UrlDecode( secretKey.toUtf8()));

                    }

                    expectedSignature = QMessageAuthenticationCode::hash(dataToSign, secretKey.toUtf8(), QCryptographicHash::Sha256)
                                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);


                }
                else if (Algorithme == "HS384"  ) {
                    if (checkbox_base64->isChecked()) {
                        secretKey = QString::fromUtf8(base64UrlDecode( secretKey.toUtf8()));

                    }

                    expectedSignature = QMessageAuthenticationCode::hash(dataToSign, secretKey.toUtf8(), QCryptographicHash::Sha384)
                                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
                }
                else if(Algorithme == "HS512"  ) {
                    if (checkbox_base64->isChecked()) {
                        secretKey = QString::fromUtf8(base64UrlDecode( secretKey.toUtf8()));

                    }

                    expectedSignature = QMessageAuthenticationCode::hash(dataToSign, secretKey.toUtf8(), QCryptographicHash::Sha512)
                                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
                }
                if (signature != expectedSignature) {
                    label_verification->setText("Invalid Signature");
                    label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");

                } else {
                    // Invalid Signature
                    label_verification->setText("Signature Verified");
                    label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");
                }
            }
            else {return;}
        }



    }
    QByteArray base64UrlDecode(const QByteArray &base64Url) {
        QByteArray base64 = base64Url + QByteArray((4 - base64Url.length() % 4) % 4, '=');
        base64.replace('-', '+');
        base64.replace('_', '/');
        return QByteArray::fromBase64(base64);
    }

    //generation de signateur HS*********************************************************************************
    void coded_HMACSHA256(){
        QString Algorithme = comboBox_Algrithme->currentText();
        QString key_pravite;

        if (Algorithme == "HS256"  ) {
            key_pravite= verify_textedit->toPlainText().toUtf8();
        }

        if (checkbox_base64->isChecked()) {
            key_pravite = QString::fromUtf8(base64UrlDecode( key_pravite.toUtf8()));

        }

        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString firstPart =tokenParts.value(0);
        QString secondPart =tokenParts.value(1);
        QString headerText = header_textedit->toPlainText();
        QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

        if (headerDocument.isNull() || !headerDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON", "The header is not valid JSON.");

            return;
        }

        // Vérifier si le payload est un JSON valide
        QString payloadText = paylood_textedit->toPlainText();
        payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

        QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

        if (payloadDocument.isNull() || !payloadDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON", "The payload is not valid JSON.");

            return;
        }

        QByteArray dataToSign = tokenParts.value(0).toUtf8() + "." + secondPart.toUtf8();
        QByteArray signature = QMessageAuthenticationCode::hash(dataToSign, key_pravite.toUtf8(), QCryptographicHash::Sha256)
                                   .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

        // Create the JWT token
        QString jwtToken = QString("%1.%2.%3").arg(QString(firstPart), QString(secondPart), QString(signature));

        token_textedit->setPlainText(jwtToken);
    }
    void coded_HMACSHA384(){
        QString Algorithme = comboBox_Algrithme->currentText();
        QString key_pravite;

        if (Algorithme == "HS384"  ) {
            key_pravite= verify_textedit->toPlainText().toUtf8();
        }


        if (checkbox_base64->isChecked()) {
            key_pravite = QString::fromUtf8(base64UrlDecode( key_pravite.toUtf8()));

        }

        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString firstPart =tokenParts.value(0);
        QString secondPart =tokenParts.value(1);
        QString headerText = header_textedit->toPlainText();
        QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

        if (headerDocument.isNull() || !headerDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON", "The header is not valid JSON.");

            return;
        }

        // Vérifier si le payload est un JSON valide
        QString payloadText = paylood_textedit->toPlainText();
        payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

        QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

        if (payloadDocument.isNull() || !payloadDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON", "The payload is not valid JSON.");

            return;
        }
        QByteArray dataToSign = tokenParts.value(0).toUtf8() + "." + secondPart.toUtf8();
        QByteArray signature = QMessageAuthenticationCode::hash(dataToSign, key_pravite.toUtf8(), QCryptographicHash::Sha384)
                                   .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

        // Create the JWT token
        QString jwtToken = QString("%1.%2.%3").arg(QString(firstPart), QString(secondPart), QString(signature));

        token_textedit->setPlainText(jwtToken);
    }
    void coded_HMACSHA512(){
        QString Algorithme = comboBox_Algrithme->currentText();
        QString key_pravite;

        if (Algorithme == "HS512"  ) {
            key_pravite= verify_textedit->toPlainText().toUtf8();
        }

        if (checkbox_base64->isChecked()) {
            key_pravite = QString::fromUtf8(base64UrlDecode( key_pravite.toUtf8()));

        }

        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString firstPart =tokenParts.value(0);
        QString secondPart =tokenParts.value(1);
        QString headerText = header_textedit->toPlainText();
        QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

        if (headerDocument.isNull() || !headerDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON", "The header is not valid JSON.");

            return;
        }

        // Vérifier si le payload est un JSON valide
        QString payloadText = paylood_textedit->toPlainText();
        payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

        QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

        if (payloadDocument.isNull() || !payloadDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON","The payload is not valid JSON.");

            return;
        }
        QByteArray dataToSign = tokenParts.value(0).toUtf8() + "." + secondPart.toUtf8();
        QByteArray signature = QMessageAuthenticationCode::hash(dataToSign, key_pravite.toUtf8(), QCryptographicHash::Sha512)
                                   .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

        // Create the JWT token
        QString jwtToken = QString("%1.%2.%3").arg(QString(firstPart), QString(secondPart), QString(signature));

        token_textedit->setPlainText(jwtToken);
    }


    //RSA*******************************************************************************************

    void coded_RSASHA256() {
        QString Algorithme = comboBox_Algrithme->currentText();

        if (Algorithme == "RS256") {
            QString privateKeyString = textedit_pravite->toPlainText();

            RSA* privateKey = loadPrivateKeyFromString(privateKeyString);

            if (!privateKey) {
                return; // Arrêter si la clé n'a pas pu être chargée
            }

            // Récupérer le texte à signer
            QString currentTokenText = token_textedit->toPlainText();
            QStringList tokenParts = currentTokenText.split('.');
            QString header = tokenParts.value(0);
            QString payload = tokenParts.value(1);
            QString headerText = header_textedit->toPlainText();
            QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

            if (headerDocument.isNull() || !headerDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON", "The header is not valid JSON.");
                RSA_free(privateKey);
                return;
            }

            // Verifier si le payload est un JSON valide
            QString payloadText = paylood_textedit->toPlainText();
            payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

            QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

            if (payloadDocument.isNull() || !payloadDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON",  "The payload is not valid JSON.");
                RSA_free(privateKey);
                return;
            }
            QByteArray signatureInput = (header + "." + payload).toUtf8();

            // Calculer le hachage SHA-256 des donnees a signer
            QByteArray hash = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha256);

            // Signature
            unsigned char* sig = new unsigned char[RSA_size(privateKey)];
            unsigned int sigLen;
            if (RSA_sign(NID_sha256, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), sig, &sigLen, privateKey) != 1) {
                QMessageBox::critical(this, "ERREUR", "Error signing RSA");
                delete[] sig;
                RSA_free(privateKey);
                return;
            }

            QByteArray signatureBytes = QByteArray(reinterpret_cast<const char*>(sig), sigLen);
            delete[] sig;

            // Convertir en base64url
            QString base64Signature = signatureBytes.toBase64().replace('+', '-').replace('/', '_').replace("=", "");

            // Mettre à jour le token avec la signature
            QString signedToken = currentTokenText + "." + base64Signature;
            token_textedit->setPlainText(signedToken);

            RSA_free(privateKey);
        }
    }

    void coded_RSASHA384() {
        QString Algorithme = comboBox_Algrithme->currentText();

        if (Algorithme == "RS384") {
            QString privateKeyString = textedit_pravite->toPlainText();

            RSA* privateKey = loadPrivateKeyFromString(privateKeyString);

            if (!privateKey) {
                return; // Arrêter si la clé n'a pas pu être chargée
            }

            // Récupérer le texte à signer
            QString currentTokenText = token_textedit->toPlainText();
            QStringList tokenParts = currentTokenText.split('.');
            QString header = tokenParts.value(0);
            QString payload = tokenParts.value(1);
            QString headerText = header_textedit->toPlainText();
            QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

            if (headerDocument.isNull() || !headerDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON","The header is not valid JSON.");
                RSA_free(privateKey);
                return;
            }

            // Vérifier si le payload est un JSON valide
            QString payloadText = paylood_textedit->toPlainText();
            payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

            QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

            if (payloadDocument.isNull() || !payloadDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON", "Le texte du payload n'est pas un JSON valide.");
                RSA_free(privateKey);
                return;
            }
            QByteArray signatureInput = (header + "." + payload).toUtf8();

            // Calculer le hachage SHA-384 des données à signer
            QByteArray hash = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha384);

            // Signature
            unsigned char* sig = new unsigned char[RSA_size(privateKey)];
            unsigned int sigLen;
            if (RSA_sign(NID_sha384, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), sig, &sigLen, privateKey) != 1) {
                QMessageBox::critical(this, "ERREUR", "Erreur lors de la signature RSA");
                delete[] sig;
                RSA_free(privateKey);
                return;
            }

            QByteArray signatureBytes = QByteArray(reinterpret_cast<const char*>(sig), sigLen);
            delete[] sig;

            // Convertir en base64url
            QString base64Signature = signatureBytes.toBase64().replace('+', '-').replace('/', '_').replace("=", "");

            // Mettre à jour le token avec la signature
            QString signedToken = currentTokenText + "." + base64Signature;
            token_textedit->setPlainText(signedToken);

            RSA_free(privateKey);
        }
    }

    void coded_RSASHA512() {
        QString Algorithme = comboBox_Algrithme->currentText();

        if (Algorithme == "RS512") {
            QString privateKeyString = textedit_pravite->toPlainText();

            RSA* privateKey = loadPrivateKeyFromString(privateKeyString);

            if (!privateKey) {
                return; // Arrêter si la clé n'a pas pu être chargée
            }

            // Récupérer le texte à signer
            QString currentTokenText = token_textedit->toPlainText();
            QStringList tokenParts = currentTokenText.split('.');
            QString header = tokenParts.value(0);
            QString payload = tokenParts.value(1);
            QString headerText = header_textedit->toPlainText();
            QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

            if (headerDocument.isNull() || !headerDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON", "Le texte du header n'est pas un JSON valide.");
                RSA_free(privateKey);
                return;
            }

            // Vérifier si le payload est un JSON valide
            QString payloadText = paylood_textedit->toPlainText();
            payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

            QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

            if (payloadDocument.isNull() || !payloadDocument.isObject()) {
                QMessageBox::critical(this, "Erreur JSON", "Le texte du payload n'est pas un JSON valide.");
                RSA_free(privateKey);
                return;
            }
            QByteArray signatureInput = (header + "." + payload).toUtf8();

            // Calculer le hachage SHA-512 des données à signer
            QByteArray hash = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha512);

            // Signature
            unsigned char* sig = new unsigned char[RSA_size(privateKey)];
            unsigned int sigLen;
            if (RSA_sign(NID_sha512, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), sig, &sigLen, privateKey) != 1) {
                QMessageBox::critical(this, "ERREUR", "Erreur lors de la signature RSA");
                delete[] sig;
                RSA_free(privateKey);
                return;
            }

            QByteArray signatureBytes = QByteArray(reinterpret_cast<const char*>(sig), sigLen);
            delete[] sig;

            // Convertir en base64url
            QString base64Signature = signatureBytes.toBase64().replace('+', '-').replace('/', '_').replace("=", "");

            // Mettre à jour le token avec la signature
            QString signedToken = currentTokenText + "." + base64Signature;
            token_textedit->setPlainText(signedToken);

            RSA_free(privateKey);
        }
    }
    //validation RS**************************************************************************************
    bool validate_RSASHA256() {
        QString publicKeyString = textedit_public->toPlainText();

        RSA* publicKey = loadPublicKeyFromString(publicKeyString);

        if (!publicKey) {
            return false; // Arrêter si la clé n'a pas pu être chargée
        }

        // Récupérer le texte signé
        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString header = tokenParts.value(0);
        QString payload = tokenParts.value(1);
        QString signature = tokenParts.value(2);

        QByteArray signatureBytes = base64UrlDecode(signature.toUtf8());

        // Calculer le hachage SHA-256 des données à vérifier
        QByteArray signedData = (header + "." + payload).toUtf8();
        QByteArray hash = QCryptographicHash::hash(signedData, QCryptographicHash::Sha256);

        // Vérifier la signature
        int verifyResult = RSA_verify(NID_sha256, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), reinterpret_cast<const unsigned char*>(signatureBytes.constData()), signatureBytes.length(), publicKey);

        RSA_free(publicKey);

        if (verifyResult == 0) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            return false;
        } else {
            label_verification->setText("Signature Verified");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");
            return true;
        }
    }

    bool validate_RSASHA384() {
        QString publicKeyString = textedit_public->toPlainText();

        RSA* publicKey = loadPublicKeyFromString(publicKeyString);

        if (!publicKey) {
            return false; // Arrêter si la clé n'a pas pu être chargée
        }

        // Récupérer le texte signé
        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString header = tokenParts.value(0);
        QString payload = tokenParts.value(1);
        QString signature = tokenParts.value(2);

        QByteArray signatureBytes = base64UrlDecode(signature.toUtf8());

        // Calculer le hachage SHA-384 des données à vérifier
        QByteArray signedData = (header + "." + payload).toUtf8();
        QByteArray hash = QCryptographicHash::hash(signedData, QCryptographicHash::Sha384);

        // Vérifier la signature
        int verifyResult = RSA_verify(NID_sha384, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), reinterpret_cast<const unsigned char*>(signatureBytes.constData()), signatureBytes.length(), publicKey);

        RSA_free(publicKey);

        if (verifyResult == 0) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            return false;
        } else {
            label_verification->setText("Signature Verified");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");
            return true;
        }
    }

    bool validate_RSASHA512() {
        QString publicKeyString = textedit_public->toPlainText();

        RSA* publicKey = loadPublicKeyFromString(publicKeyString);

        if (!publicKey) {
            return false; // Arrêter si la clé n'a pas pu être chargée
        }

        // Récupérer le texte signé
        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');
        QString header = tokenParts.value(0);
        QString payload = tokenParts.value(1);
        QString signature = tokenParts.value(2);

        QByteArray signatureBytes = base64UrlDecode(signature.toUtf8());

        // Calculer le hachage SHA-512 des données à vérifier
        QByteArray signedData = (header + "." + payload).toUtf8();
        QByteArray hash = QCryptographicHash::hash(signedData, QCryptographicHash::Sha512);

        // Vérifier la signature
        int verifyResult = RSA_verify(NID_sha512, reinterpret_cast<const unsigned char*>(hash.constData()), hash.length(), reinterpret_cast<const unsigned char*>(signatureBytes.constData()), signatureBytes.length(), publicKey);

        RSA_free(publicKey);

        if (verifyResult == 0) {
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
            return false;
        } else {
            label_verification->setText("Signature Verified");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");
            return true;
        }
    }


    //delet************************************************************************************************
    void deleteTokenText() {

        token_textedit->clear();

    }


private slots:

    void updateHeaderText() {
        QString algorithm = comboBox_Algrithme->currentText();
        QString headerText = QString("{\"alg\": \"%1\", \"typ\": \"JWT\"}").arg(algorithm);
        header_textedit->setTextColor(QColor("red"));
       header_textedit->setStyleSheet("font-weight: bold; font-size: 14px;");
        header_textedit->setPlainText(headerText);
    }
    void encode() {
        QString headerText = header_textedit->toPlainText();
        QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());

        if (headerDocument.isNull() || !headerDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON","The header is not valid JSON.");
            return;
        }
        QByteArray headerByteArray = headerDocument.toJson(QJsonDocument::Compact);
        QString base64Encoded = headerByteArray.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        token_textedit->setPlainText(base64Encoded);
    }
    void updatePayloodText()
    {
        QMap<QString, QVariant> payload_data;
        QString payload_json;
        QString algorithm = comboBox_Algrithme->currentText();
        if(algorithm=="HS256" ||algorithm=="HS384" || algorithm=="HS512" ){
            payload_data["sub"] = "1234567890";
            payload_data["name"] = "John Doe";
            payload_data["iat"] = 1516239022;
            payload_json = QStringLiteral(R"({"sub":"%1","name":"%2","iat":%3})")
                               .arg(payload_data["sub"].toString(),
                                    payload_data["name"].toString(),
                                    QString::number(payload_data["iat"].toLongLong()));

            // Encodez la chaîne JSON en base64url

        }
        else{
            payload_data["sub"] = "1234567890";
            payload_data["name"] = "John Doe";
            payload_data["iat"] = 1516239022;
            payload_data["admin"]= true;

            // Construction manuelle de la chaîne JSON
            payload_json = QStringLiteral(R"({"sub":"%1","name":"%2","admin":%3,"iat":%4})")
                               .arg(payload_data["sub"].toString(),
                                    payload_data["name"].toString(),
                                    payload_data["admin"].toString(),
                                    payload_data["iat"].toString());

            // Encodez la chaîne JSON en base64url

        }
        paylood_textedit->setTextColor(QColor("#AF7AC5"));
        paylood_textedit->setStyleSheet("font-weight: bold; font-size: 14px;");
        paylood_textedit->setPlainText(payload_json);
    }

    void encodePayload() {
        QString payloadText = paylood_textedit->toPlainText();
        payloadText = QString::fromUtf8(removeLineEndings(payloadText.toUtf8()));

        QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

        if (payloadDocument.isNull() || !payloadDocument.isObject()) {
            QMessageBox::critical(this, "Erreur JSON","The payload is not valid JSON.");
            return;
        }

        QByteArray encoded_payload = payloadText.toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals).trimmed();

        QString currentTokenText = token_textedit->toPlainText();
        QString newTokenText = currentTokenText + "." + encoded_payload;
        token_textedit->setPlainText(newTokenText);
    }
    void verifySignature() {
        // Get the text from header and payload
        QString headerText = header_textedit->toPlainText();
        QString payloadText = paylood_textedit->toPlainText();

        // Perform your signature verification logic here
        // For simplicity, let's assume the verification succeeds if both header and payload are valid JSON
        QJsonDocument headerDocument = QJsonDocument::fromJson(headerText.toUtf8());
        QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadText.toUtf8());

        if (!headerDocument.isNull() && headerDocument.isObject() &&
            !payloadDocument.isNull() && payloadDocument.isObject()) {
            // Signature Verified
            label_verification->setText("Signature Verified");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:#00B9F1;background-color: white;");
        } else {
            // Invalid Signature
            label_verification->setText("Invalid Signature");
            label_verification->setStyleSheet("font: bold 18px ; font-family: Arial;color:red;background-color: white;");
        }
    }


    void decode() {
        QString currentTokenText = token_textedit->toPlainText();
        QStringList tokenParts = currentTokenText.split('.');

        if (tokenParts.size() != 3) {
            QMessageBox::critical(this, "Invalid Token", "Token must have three parts.");
            return;
        }

        QString encodedHeader = tokenParts.value(0);
        QString encodedPayload = tokenParts.value(1);

        QByteArray decodedHeader = base64UrlDecode(encodedHeader.toUtf8());
        QByteArray decodedPayload = base64UrlDecode(encodedPayload.toUtf8());

        QJsonDocument headerDocument = QJsonDocument::fromJson(decodedHeader);
        QJsonDocument payloadDocument = QJsonDocument::fromJson(decodedPayload);

        if (headerDocument.isNull() || payloadDocument.isNull()) {
            QMessageBox::critical(this, "Invalid Token", "Invalid JSON in Header or Payload.");
            return;
        }

        QString headerText = headerDocument.toJson(QJsonDocument::Indented);
        QString payloadText = payloadDocument.toJson(QJsonDocument::Indented);

        header_textedit->setPlainText(headerText);
        paylood_textedit->setPlainText(payloadText);

        // Check if the header contains "alg" field
        if (headerDocument.isObject() && headerDocument.object().contains("alg")) {
            QString algorithm = headerDocument.object().value("alg").toString();

            // Update comboBox_Algrithme with the detected algorithm
            int index = comboBox_Algrithme->findText(algorithm);
            if (index != -1) {
                comboBox_Algrithme->setCurrentIndex(index);
            } else {
                QMessageBox::warning(this, "Algorithm not found", "Algorithme dans Header non pris en charge.");
                return;
            }


            // Update the signature frame accordingly
            update_sig();

            validate_RSASHA();

        } else {
            QMessageBox::warning(this, "Missing Algorithm", "Header ne contient pas le champ 'alg'.");
        }
    }



private:
    QVBoxLayout* mainlayout;
    QHBoxLayout* hlayout1;
    QFormLayout* formlayout;
    QGridLayout* vecbox;
    QVBoxLayout* vecbox1;
    QVBoxLayout* vecbox2;
    QVBoxLayout* vecbox3;
    QVBoxLayout* vecbox4;
    QVBoxLayout* vecbox5;

    QGroupBox* group1;
    QGroupBox* group3;
    QLabel* label_verification;
    QLabel* label_text;
    QLabel* label_parenthese;
    QLabel* label_parenthese2;
    QLabel* label_hedear;
    QLabel* label_paylood;
    QLabel* label_verify;
    QLabel* label_token;
    QLabel* label_algorithme;
    QLabel* label_decoded;
    QLabel* label_sign;

    QTextEdit* header_textedit;
    QTextEdit* paylood_textedit;
    QTextEdit* verify_textedit;
    QTextEdit* token_textedit;
    QTextEdit* textedit_pravite;
    QTextEdit* textedit_public;

    QComboBox* comboBox_Algrithme;

    QCheckBox* checkbox_base64;

    QPushButton* codageButton;
    QPushButton* deleteButton;

    QPushButton* decodageButton;
    QPushButton* validationButton;

    QFrame* frame;
};

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    Window window;
    // Appliquer une feuille de style pour personnaliser l'apparence des widgets
    QString styleSheet = R"(
        /* Style pour la fenêtre principale */
         QWidget {
         background-color: #E5E8E8 ; /* Définir la couleur d'arrière-plan en blanc */
        }

        /* Style pour les groupes de widgets */
        QGroupBox {
            background-color: #ffffff;
            border: 1px solid #ccc;
            border-radius: 8px;
            margin-top: 10px;
            padding: 10px;
        }

        /* Style pour les boutons */
        QPushButton {
            background-color: #A569BD;
            border: none;
            color: white;
            padding: 10px 20px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 5px;
        }

        QPushButton:hover {
            background-color: #EDA5F4 ;
        }

        /* Style pour les menus */
        QMenuBar {
            background-color: #333;
            color: #fff;
        }

        QMenuBar::item {
            background-color: transparent;
            color: #fff;
            padding: 2px 10px;
        }

        QMenuBar::item:selected {
            background-color: #666;
        }

        /* Style pour les labels */
        QLabel {
            font-size: 16px;
            color: #333;
        }

        /* Style pour les zones de texte */
        QTextEdit {
            background-color: #fff;
            border: 1px solid #ccc;
            padding: 5px;
            border-radius: 5px;
        }
    )";// Appliquer une feuille de style pour personnaliser l'apparence des QTextEdit

    styleSheet += R"(
    /* Styles pour les zones de texte (Header) */
    QTextEdit#headerTextEdit {
        background-color: #eff0f1;
        border: 1px solid #ccc;
        padding: 5px;
        border-radius: 5px;
        font-family: Arial;
        font-size: 12px;
        color: #333;
    }

    /* Styles pour les zones de texte (Payload) */
    QTextEdit#payloadTextEdit {
        background-color: #f9f9f9;
        border: 1px solid #ccc;
        padding: 5px;
        border-radius: 5px;
        font-family: Arial;
        font-size: 12px;
        color: #333;
    }
)";
    styleSheet += R"(
    /* Style pour vecbox5 */
    QWidget#vecbox5 {
        background-color: #C0C0C0; /* Définir la couleur d'arrière-plan en gris */
        /* Autres propriétés de style si nécessaire */
    }
)";
    // Appliquer le style à l'application
    a.setStyleSheet(styleSheet);
    QScrollArea* scrollArea = new QScrollArea;
    scrollArea->setWidget(&window);
    scrollArea->setWidgetResizable(true);

    scrollArea->show();
    QIcon icon("C:/Projet_C++_JWT/iconeJWT.png");  // Remplacez avec le chemin de votre icône
    a.setWindowIcon(icon);
    window.show();
    window.updateS();
    return a.exec();
}
