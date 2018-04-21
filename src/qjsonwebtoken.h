/**
\file
\version 1.0
\date    22/06/2016
\author  JGB
\brief   JWT (JSON Web Token) Implementation in Qt C++
*/

// The MIT License(MIT)
// Copyright(c) <2016> <Juan Gonzalez Burgos>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef QJSONWEBTOKEN_H
#define QJSONWEBTOKEN_H

#include <QObject>
#include <QMessageAuthenticationCode>
#include <QSharedPointer>
#include <QJsonDocument>
#include <QJsonObject>

#ifdef USE_QCA
#include <QtCrypto>
#endif // USE_QCA


// forward declaration
class QJsonWebKey;


/**

\brief   QJsonWebToken : JWT (JSON Web Token) Implementation in Qt C++

## Introduction

This class implements a subset of the [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) 
open standard [RFC 7519](https://tools.ietf.org/html/rfc7519).

Currently this implementation only supports the following algorithms:

Alg   | Parameter Value	Algorithm
----- | ------------------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm

### Include

In order to include this class in your project, in the qt project **.pro** file add the lines:

```
HEADERS  += ./src/qjsonwebtoken.h
SOURCES  += ./src/qjsonwebtoken.cpp
```

### Usage

The repository of this project includes examples that demonstrate the use of this class:

* ./examples/jwtcreator/  : Example that shows how to create a JWT with your custom *payload*.

* ./examples/jwtverifier/ : Example that shows how to validate a JWT with a given *secret*.

*/
class QJsonWebToken
{

public:

	/**

	\brief Constructor.
	\return A new instance of QJsonWebToken.

	Creates a default QJsonWebToken instance with *HS256 algorithm*, empty *payload*
	and empty *secret*.

	*/
	QJsonWebToken();                            // TODO : improve with params

	/**

	\brief Copy Construtor.
	\param other Other QJsonWebToken to copy from.
	\return A new instance of QJsonWebToken with same contents as the *other* instance.
	
	Copies to the new instance the JWT *header*, *payload*, *signature*, *secret* and *algorithm*.

	*/
	QJsonWebToken(const QJsonWebToken &other) = default;

	/**

	\brief Returns the JWT *header* as a QJsonDocument.
	\return JWT *header* as a QJsonDocument.

	*/
	QJsonDocument getHeaderJDoc();

	/**

	\brief Returns the JWT *header* as a QString.
	\param format Defines the format of the JSON returned.
	\return JWT *header* as a QString.

	Format can be *QJsonDocument::JsonFormat::Indented* or *QJsonDocument::JsonFormat::Compact*

	*/
	QString       getHeaderQStr(bool pretty=true) const;
	QByteArray    getHeaderJson() const;

	/**

	\brief Sets the JWT *header* from a QJsonDocument.
	\param jdocHeader JWT *header* as a QJsonDocument.
	\return true if the header was set, false if the header was not set.

	This method checks for a valid header format and returns false if the header is invalid.

	*/
	bool          setHeaderJDoc(const QJsonDocument &jdocHeader);

	/**

	\brief Sets the JWT *header* from a QString.
	\param jdocHeader JWT *header* as a QString.
	\return true if the header was set, false if the header was not set.

	This method checks for a valid header format and returns false if the header is invalid.

	*/
	bool          setHeaderQStr(QString strHeader);
	bool          setHeaderJson(const QByteArray &jsonHeader);

	/**

	\brief Returns the JWT *payload* as a QJsonDocument.
	\return JWT *payload* as a QJsonDocument.

	*/
	QJsonDocument getPayloadJDoc();

	/**

	\brief Returns the JWT *payload* as a QString.
	\param format Defines the format of the JSON returned.
	\return JWT *payload* as a QString.

	Format can be *QJsonDocument::JsonFormat::Indented* or *QJsonDocument::JsonFormat::Compact*

	*/
	QString       getPayloadQStr(bool pretty=true) const;
	QByteArray    getPayloadJson() const;

	/**

	\brief Sets the JWT *payload* from a QJsonDocument.
	\param jdocHeader JWT *payload* as a QJsonDocument.
	\return true if the payload was set, false if the payload was not set.

	This method checks for a valid payload format and returns false if the payload is invalid.

	*/
	bool          setPayloadJDoc(const QJsonDocument &jdocPayload);

	/**

	\brief Sets the JWT *payload* from a QString.
	\param jdocHeader JWT *payload* as a QString.
	\return true if the payload was set, false if the payload was not set.

	This method checks for a valid payload format and returns false if the payload is invalid.

	*/
	bool          setPayloadQStr(const QString &strPayload);
	bool          setPayloadJson(const QByteArray &jsonPayload);

	/**

	\brief Returns the JWT *signature* as a QByteArray.
	\return JWT *signature* as a decoded QByteArray.
	*/
	QByteArray    getSignature() const;

	/**

	\brief Returns the JWT *signature* as a QByteArray.
	\return JWT *signature* as a **base64 encoded** QByteArray.
	*/
	QByteArray    getSignatureBase64() const;

	/**

	\brief Returns the JWK.
	\return JsonWebKey.

	*/
	QSharedPointer<QJsonWebKey> getKey() const;

	/**

	\brief Sets the JWK.
	\param key JsonWebKey.
	\return true if the key was set, false if the key was not set.

	This method checks for a valid key format and returns false if the key is invalid.

	*/
	bool          setKey(const QSharedPointer<QJsonWebKey> &key);

	/**

	\brief Returns the JWT *algorithm* as a QString.
	\return JWT *algorithm* as a QString.

	*/
	QString       getAlgorithmStr() const;

	/**

	\brief Sets the JWT *algorithm* from a QString.
	\param strAlgorithm JWT *algorithm* as a QString.
	\return true if the algorithm was set, false if the algorithm was not set.

	This method checks for a valid supported algorithm. Valid values are:

	"HS256", "HS384" and "HS512".

	\sa QJsonWebToken::supportedAlgorithms().

	*/
	bool          setAlgorithmStr(const QString &strAlgorithm);

	/**

	\brief Returns the complete JWT as a QString.
	\return Complete JWT as a QString.

	The token has the form:

	```
	xxxxx.yyyyy.zzzzz
	```

	where:
	
	- *xxxxx* is the *header* enconded in base64.
	- *yyyyy* is the *payload* enconded in base64.
	- *zzzzz* is the *signature* enconded in base64.

	*/
	QString       getToken() const;

	/**

	\brief Sets the complete JWT as a QString.
	\param strToken Complete JWT as a QString.
	\return true if the complete JWT was set, false if not set.

	This method checks for a valid JWT format. It overwrites the *header*,
	*payload* , *signature* and *algorithm*. It does **not** overwrite the secret.

	\sa QJsonWebToken::getToken().

	*/
	bool          setToken(const QString &strToken);

	/**

	\brief Checks validity of current JWT with respect to secret.
	\return true if the JWT is valid with respect to secret, else false.

	Uses the current *secret* to calculate a temporary *signature* and compares it to the
	current signature to check if they are the same. If they are, true is returned, if not then
	false is returned.

	*/
	bool          isValid() const;
	bool          isValidSignature() const;
	bool          isValidJson() const;

	/**

	\brief Creates a QJsonWebToken instance from the complete JWT and a secret.
	\param strToken Complete JWT as a QString.
	\param secret Secret as a QByteArray.
	\return Instance of QJsonWebToken.

	The JWT provided must have a valid format, else a QJsonWebToken instance with default
	values will be returned.

	*/
	static QJsonWebToken fromTokenAndKey(const QString &strToken, const QSharedPointer<QJsonWebKey> &key);

	/**

	\brief Returns a list of the supported algorithms.
	\return List of supported algorithms as a QStringList.

	*/
	static QStringList supportedAlgorithms();

	/**

	\brief Convenience method to append a claim to the *payload*.
	\param strClaimType The claim type as a QString.
	\param strValue The value type as a QString.

	Both parameters must be non-empty. If the claim type already exists, the current
	claim value is updated.

	*/
	void appendClaim(const QString &strClaimType, const QJsonValue &value);

	/**

	\brief Convenience method to remove a claim from the *payload*.
	\param strClaimType The claim type as a QString.

	If the claim type does not exist in the *payload*, then this method does nothins.

	*/
	void removeClaim(const QString &strClaimType);

	static bool isValidHeader(const QJsonDocument &jdocHeader);
	static bool isValidHeader(const QByteArray &byteHeader);
	static bool isValidPayload(const QJsonDocument &jdocPayload);
	static bool isValidPayload(const QByteArray &bytePayload);

protected:
	void updateHeader(const QJsonDocument &jdocHeader);
	void updateHeader(const QByteArray &byteHeader);
	void updateHeaderAlgorithm();
	void updatePayload(const QJsonDocument &jdocPayload);
	void updatePayload(const QByteArray &bytePayload);
	void updateSignature();

private:
	// properties
	QByteArray    m_byteHeader;    // original
	QByteArray    m_bytePayload;   // original
	QJsonDocument m_jdocHeader;	   // unencoded
	QJsonDocument m_jdocPayload;   // unencoded
	QByteArray    m_byteSignature; // unencoded
	QString       m_strAlgorithm;

	// helpers
	QByteArray    m_byteAllData;

	QSharedPointer<QJsonWebKey> m_jwk;

	static bool isAlgorithmSupported(QString strAlgorithm);
};


class QJsonWebKey
{
public:
	typedef enum {
		Octet,
		RSA,
		EC,
	} KeyType;

	virtual ~QJsonWebKey()
	{}

	virtual KeyType type() const = 0;
	virtual bool isPrivate() const = 0;
	virtual QByteArray sign(const QString &algorithm, const QByteArray &data) const = 0;
	virtual bool verify(const QString &algorithm, const QByteArray &signature, const QByteArray &data) const = 0;

	virtual QSharedPointer<QJsonWebKey> toPublic() = 0;
	virtual QByteArray toJson() const = 0;

	/**

	\brief Returns a list of the supported algorithms.
	\return List of supported algorithms as a QStringList.

	*/
	virtual QStringList supportedAlgorithms() const = 0;

	static QSharedPointer<QJsonWebKey> fromJsonWebKey(const QByteArray &jwk);
	static QSharedPointer<QJsonWebKey> fromOctet(const QByteArray &data);
	static QSharedPointer<QJsonWebKey> generateRSAPrivateKey(int bits);
};


#endif // QJSONWEBTOKEN_H
