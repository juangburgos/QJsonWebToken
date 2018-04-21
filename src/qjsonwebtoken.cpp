// The MIT License(MIT)
// Copyright(c) <2016> <Juan Gonzalez Burgos>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "qjsonwebtoken.h"

#include <QDebug>

// RFC7515 Section 2 Terminology
// Base64url Encoding:
//   Base64 encoding using the URL- and filename-safe character set
//   defined in Section 5 of RFC 4648 [RFC4648], with all trailing '='
//   characters omitted (as permitted by Section 3.2) and without the
//   inclusion of any line breaks, whitespace, or other additional
//   characters.  Note that the base64url encoding of the empty octet
//   sequence is the empty string.  (See Appendix C for notes on
//   implementing base64url encoding without padding.)
QByteArray toBase64Url(const QByteArray &data)
{
	return data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

QByteArray fromBase64Url(const QByteArray &base64)
{
	return QByteArray::fromBase64(base64, QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

QJsonWebToken::QJsonWebToken() :
	m_byteHeader(),
	m_bytePayload(),
	m_jdocHeader(),
	m_jdocPayload(QJsonDocument::fromJson("{}")),
	m_byteSignature(),
	m_byteSecret(),
	m_strAlgorithm(),
	// default for random generation
	m_intRandLength(10),
	m_strRandAlphanum("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
	m_byteAllData()
{
	// create the header with default algorithm
	setAlgorithmStr("HS256");
}

QJsonDocument QJsonWebToken::getHeaderJDoc()
{
	return m_jdocHeader;
}

QString QJsonWebToken::getHeaderQStr(bool pretty) const
{
	if (pretty)
	{
		return m_jdocHeader.toJson(QJsonDocument::JsonFormat::Indented);
	}
	else
	{
		return QString::fromUtf8(m_byteHeader);
	}
}

QByteArray QJsonWebToken::getHeaderJson() const
{
	return m_byteHeader;
}

bool QJsonWebToken::setHeaderJDoc(const QJsonDocument &jdocHeader)
{
	if (!isValidHeader(jdocHeader))
	{
		return false;
	}

	updateHeader(jdocHeader);

	return true;
}

bool QJsonWebToken::setHeaderQStr(QString strHeader)
{
	return setHeaderJson(strHeader.toUtf8());
}

bool QJsonWebToken::setHeaderJson(const QByteArray &jsonHeader)
{
	if (!isValidHeader(jsonHeader))
	{
		return false;
	}

	updateHeader(jsonHeader);

	return true;
}

QJsonDocument QJsonWebToken::getPayloadJDoc()
{
	return m_jdocPayload;
}

QString QJsonWebToken::getPayloadQStr(bool pretty) const
{
	if (pretty)
	{
		return m_jdocPayload.toJson(QJsonDocument::JsonFormat::Indented);
	}
	else
	{
		return QString::fromUtf8(m_bytePayload);
	}
}

QByteArray QJsonWebToken::getPayloadJson() const
{
	return m_bytePayload;
}

bool QJsonWebToken::setPayloadJDoc(const QJsonDocument &jdocPayload)
{
	if (!isValidPayload(jdocPayload))
	{
		return false;
	}

	updatePayload(jdocPayload);

	return true;
}

bool QJsonWebToken::setPayloadQStr(const QString &strPayload)
{
	return setPayloadJson(strPayload.toUtf8());
}

bool QJsonWebToken::setPayloadJson(const QByteArray &jsonPayload)
{
	if (!isValidPayload(jsonPayload))
	{
		return false;
	}

	updatePayload(jsonPayload);

	return true;
}

QByteArray QJsonWebToken::getSignature() const
{
	return m_byteSignature;
}

QByteArray QJsonWebToken::getSignatureBase64() const
{
	return toBase64Url(getSignature());
}

QByteArray QJsonWebToken::getSecret() const
{
	return m_byteSecret;
}

bool QJsonWebToken::setSecret(const QByteArray &byteSecret)
{
	if (byteSecret.isEmpty() || byteSecret.isNull())
	{
		return false;
	}

	m_byteSecret = byteSecret;
	updateSignature();

	return true;
}

void QJsonWebToken::setRandomSecret()
{
	m_byteSecret.resize(m_intRandLength);
	QByteArray byteRandAlphanum = m_strRandAlphanum.toUtf8();
	for (int i = 0; i < m_intRandLength; ++i)
	{
		m_byteSecret[i] = byteRandAlphanum.at(rand() % (byteRandAlphanum.length() - 1));
	}
}

QString QJsonWebToken::getAlgorithmStr() const
{
	return m_strAlgorithm;
}

bool QJsonWebToken::setAlgorithmStr(const QString &strAlgorithm)
{
	// check if supported algorithm
	if (!isAlgorithmSupported(strAlgorithm))
	{
		return false;
	}
	// set algorithm
	m_strAlgorithm = strAlgorithm;
	// modify header
	setHeaderJDoc(QJsonDocument::fromJson(QObject::trUtf8("{\"typ\": \"JWT\", \"alg\" : \"").toUtf8()
                                          + m_strAlgorithm.toUtf8()
                                          + QObject::trUtf8("\"}").toUtf8()));

	return true;
}

QString QJsonWebToken::getToken() const
{
	// important to execute first to update m_byteAllData which contains header + "." + payload in base64
	QByteArray byteSignatureBase64 = getSignatureBase64();
	// compose token and return it
	return m_byteAllData + "." + byteSignatureBase64;
}

bool QJsonWebToken::setToken(const QString &strToken)
{
	// assume base64 encoded at first, if not try decoding
	bool isBase64Encoded = true;
	QStringList listJwtParts = strToken.split(".");
	// check correct size
	if (listJwtParts.count() != 3)
	{
		return false;
	}
	m_byteHeader = fromBase64Url(listJwtParts.at(0).toUtf8());
	m_bytePayload = fromBase64Url(listJwtParts.at(1).toUtf8());
	// check all parts are valid using another instance,
	// so we dont overwrite this instance in case of error
	QJsonWebToken tempTokenObj;
	if ( !tempTokenObj.setHeaderQStr(m_byteHeader) ||
		 !tempTokenObj.setPayloadQStr(m_bytePayload) )
	{
		// try unencoded
		if (!tempTokenObj.setHeaderQStr(listJwtParts.at(0)) ||
			!tempTokenObj.setPayloadQStr(listJwtParts.at(1)))
		{
			return false;
		}
		else
		{
			isBase64Encoded = false;
			m_byteHeader = listJwtParts.at(0).toUtf8();
			m_bytePayload = listJwtParts.at(1).toUtf8();
		}
	}
	// set parts on this instance
	setHeaderJson(tempTokenObj.getHeaderJson());
	setPayloadJson(tempTokenObj.getPayloadJson());
	// set specified signature
	if (isBase64Encoded)
	{ // unencode
		m_byteSignature = fromBase64Url(listJwtParts.at(2).toUtf8());
	} 
	else
	{
		m_byteSignature = listJwtParts.at(2).toUtf8();
	}
	// success
	return true;
}

QString QJsonWebToken::getRandAlphanum() const
{
	return m_strRandAlphanum;
}

void QJsonWebToken::setRandAlphanum(const QString &strRandAlphanum)
{
	if(strRandAlphanum.isNull())
	{
		return;
	}
	m_strRandAlphanum = strRandAlphanum;
}

int QJsonWebToken::getRandLength() const
{
	return m_intRandLength;
}

void QJsonWebToken::setRandLength(int intRandLength)
{
	if(intRandLength < 0 || intRandLength > 1e6)
	{
		return;
	}
	m_intRandLength = intRandLength;
}

bool QJsonWebToken::isValid() const
{
	return isValidSignature() && isValidJson();
}

bool QJsonWebToken::isValidSignature() const
{
	return m_byteSignature == calcSignature(m_byteAllData);
}

bool QJsonWebToken::isValidJson() const
{
	QJsonParseError headerError, payloadError;
	QJsonDocument header = QJsonDocument::fromJson(m_byteHeader, &headerError);
	QJsonDocument payload = QJsonDocument::fromJson(m_bytePayload, &payloadError);
	// TODO: RFC7515 Section 5.2 Message Signature o MAC Validation
	return (! header.isNull() && ! payload.isNull() && headerError.error == QJsonParseError::NoError && payloadError.error == QJsonParseError::NoError);
}

QJsonWebToken QJsonWebToken::fromTokenAndSecret(const QString &strToken, const QByteArray &byteSecret)
{
	QJsonWebToken tempTokenObj;
	// set Secret
	tempTokenObj.setSecret(byteSecret);
	// set Token
	tempTokenObj.setToken(strToken);
	// return
	return tempTokenObj;
}

void QJsonWebToken::appendClaim(const QString &strClaimType, const QJsonValue &value)
{
	// have to make a copy of the json object, modify the copy and then put it back, sigh
	QJsonObject jObj = m_jdocPayload.object();
	jObj.insert(strClaimType, value);
	setPayloadJDoc(QJsonDocument(jObj));
}

void QJsonWebToken::removeClaim(const QString &strClaimType)
{
	// have to make a copy of the json object, modify the copy and then put it back, sigh
	QJsonObject jObj = m_jdocPayload.object();
	jObj.remove(strClaimType);
	setPayloadJDoc(QJsonDocument(jObj));
}

bool QJsonWebToken::isValidHeader(const QJsonDocument &jdocHeader)
{
	return ! jdocHeader.isEmpty() && ! jdocHeader.isNull() && jdocHeader.isObject() && isAlgorithmSupported(jdocHeader.object().value("alg").toString(""));
}

bool QJsonWebToken::isValidHeader(const QByteArray &byteHeader)
{
	QJsonParseError error;
	return isValidHeader(QJsonDocument::fromJson(byteHeader, &error)) && error.error == QJsonParseError::NoError;
}

bool QJsonWebToken::isValidPayload(const QJsonDocument &jdocPayload)
{
	return ! jdocPayload.isEmpty() && ! jdocPayload.isNull() && jdocPayload.isObject();
}

bool QJsonWebToken::isValidPayload(const QByteArray &bytePayload)
{
	QJsonParseError error;
	return isValidPayload(QJsonDocument::fromJson(bytePayload, &error)) && error.error == QJsonParseError::NoError;
}

void QJsonWebToken::updateHeader(const QJsonDocument &jdocHeader)
{
	//assert(isValidHeader(jdocHeader));
	m_jdocHeader = jdocHeader;
	m_byteHeader = jdocHeader.toJson(QJsonDocument::JsonFormat::Compact);
	updateHeaderAlgorithm();
	updateSignature();
}

void QJsonWebToken::updateHeader(const QByteArray &byteHeader)
{
	//assert(isValidHeader(byteHeader));
	m_byteHeader = byteHeader;
	m_jdocHeader = QJsonDocument::fromJson(byteHeader);
	updateHeaderAlgorithm();
	updateSignature();
}

void QJsonWebToken::updateHeaderAlgorithm()
{
	//assert(isValidHeader(byteHeader));
	// set also new algorithm
	m_strAlgorithm = m_jdocHeader.object().value("alg").toString("");
}

void QJsonWebToken::updatePayload(const QJsonDocument &jdocPayload)
{
	//assert(isValidPayload(jdocPayload));
	m_jdocPayload = jdocPayload;
	m_bytePayload = jdocPayload.toJson(QJsonDocument::JsonFormat::Compact);
	updateSignature();
}

void QJsonWebToken::updatePayload(const QByteArray &bytePayload)
{
	//assert(isValidPayload(bytePayload));
	m_bytePayload = bytePayload;
	m_jdocPayload = QJsonDocument::fromJson(bytePayload);
	updateSignature();
}

void QJsonWebToken::updateSignature()
{
	// recalculate
	// get header in compact mode and base64 encoded
	QByteArray byteHeaderBase64  = toBase64Url(m_jdocHeader.toJson(QJsonDocument::JsonFormat::Compact));
	// get payload in compact mode and base64 encoded
	QByteArray bytePayloadBase64 = toBase64Url(m_jdocPayload.toJson(QJsonDocument::JsonFormat::Compact));
	// calculate signature based on chosen algorithm and secret
	m_byteAllData = byteHeaderBase64 + "." + bytePayloadBase64;
	m_byteSignature = calcSignature(m_byteAllData);
}

bool QJsonWebToken::isAlgorithmSupported(QString strAlgorithm)
{
	// TODO : support other algorithms
	if (strAlgorithm.compare("HS256", Qt::CaseInsensitive) != 0 && // HMAC using SHA-256 hash algorithm
		strAlgorithm.compare("HS384", Qt::CaseInsensitive) != 0 && // HMAC using SHA-384 hash algorithm
		strAlgorithm.compare("HS512", Qt::CaseInsensitive) != 0 /*&& // HMAC using SHA-512 hash algorithm
		strAlgorithm.compare("RS256", Qt::CaseInsensitive) != 0 && // RSA using SHA-256 hash algorithm
		strAlgorithm.compare("RS384", Qt::CaseInsensitive) != 0 && // RSA using SHA-384 hash algorithm
		strAlgorithm.compare("RS512", Qt::CaseInsensitive) != 0 && // RSA using SHA-512 hash algorithm
		strAlgorithm.compare("ES256", Qt::CaseInsensitive) != 0 && // ECDSA using P-256 curve and SHA-256 hash algorithm
		strAlgorithm.compare("ES384", Qt::CaseInsensitive) != 0 && // ECDSA using P-384 curve and SHA-384 hash algorithm
		strAlgorithm.compare("ES512", Qt::CaseInsensitive) != 0*/)  // ECDSA using P-521 curve and SHA-512 hash algorithm
	{
		return false;
	}
	return true;
}

QStringList QJsonWebToken::supportedAlgorithms()
{
	// TODO : support other algorithms
	return QStringList() << "HS256" << "HS384" << "HS512";
}

QByteArray QJsonWebToken::calcSignature(const QByteArray &data) const
{
	// calculate
	if (m_strAlgorithm.compare("HS256", Qt::CaseInsensitive) == 0)      // HMAC using SHA-256 hash algorithm
	{
		return QMessageAuthenticationCode::hash(data, m_byteSecret, QCryptographicHash::Sha256);
	}
	else if (m_strAlgorithm.compare("HS384", Qt::CaseInsensitive) == 0) // HMAC using SHA-384 hash algorithm
	{
		return QMessageAuthenticationCode::hash(data, m_byteSecret, QCryptographicHash::Sha384);
	}
	else if (m_strAlgorithm.compare("HS512", Qt::CaseInsensitive) == 0) // HMAC using SHA-512 hash algorithm
	{
		return QMessageAuthenticationCode::hash(data, m_byteSecret, QCryptographicHash::Sha512);
	}
	// TODO : support other algorithms
	else
	{
		return QByteArray();
	}
}
