#ifndef QJSONWEBTOKEN_H
#define QJSONWEBTOKEN_H

#include <QObject>
#include <QMessageAuthenticationCode>
//#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>

class QJsonWebToken
{

public:
    QJsonWebToken(); // todo : improve with params
	QJsonWebToken(const QJsonWebToken &other);  // copy constructor

	QJsonDocument getHeaderJDoc();
	QString       getHeaderQStr(QJsonDocument::JsonFormat format = QJsonDocument::JsonFormat::Indented);

	bool          setHeaderJDoc(QJsonDocument jdocHeader);
	bool          setHeaderQStr(QString strHeader);

	QJsonDocument getPayloadJDoc();
	QString       getPayloadQStr(QJsonDocument::JsonFormat format = QJsonDocument::JsonFormat::Indented);

	bool          setPayloadJDoc(QJsonDocument jdocPayload);
	bool          setPayloadQStr(QString strPayload);

	QByteArray    getSignature();		// WARNING overwrites signature
	QByteArray    getSignatureBase64(); // WARNING overwrites signature

	QString       getSecret();
	bool          setSecret(QString strSecret);
	//QString       setRandomSecret(); // TODO : implement

	QString       getAlgorithmStr();
	bool          setAlgorithmStr(QString strAlgorithm);

	QString       getToken();
	bool          setToken(QString strToken);

	bool          isValid();

	static QJsonWebToken fromTokenAndSecret(QString strToken, QString srtSecret);

	static QStringList supportedAlgorithms();

	// convenience functions

	void appendClaim(QString strClaimType, QString strValue);

	void removeClaim(QString strClaimType);

private:
	// properties
	QJsonDocument m_jdocHeader;	   // unencoded
	QJsonDocument m_jdocPayload;   // unencoded
	QByteArray    m_byteSignature; // unencoded
	QString       m_strSecret;
	QString       m_strAlgorithm;

	// helpers
	QByteArray    m_byteAllData;

	bool isAlgorithmSupported(QString strAlgorithm);
};

#endif // QJSONWEBTOKEN_H