// The MIT License(MIT)
// Copyright(c) <2016> <Juan Gonzalez Burgos>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "dialog.h"
#include "ui_dialog.h"

#include <QDebug>
#include <QDateTime>

Dialog::Dialog(QWidget *parent) :
	QDialog(parent),
	ui(new Ui::Dialog),
	hsKey(QJsonWebKey::fromOctet("mydirtysecret")),
	rsKey(nullptr)
{
	ui->setupUi(this);
	// set some tooltips
	ui->pushRemoveClaim->setToolTip("To remove a claim you just need to define the <b>Claim Type<\b>");
	ui->pushRemoveClaim->setToolTipDuration(3500);
	// set default secret
	ui->plainTextEditKey->setPlainText(QString::fromUtf8(hsKey->toJson()));
	m_jwtObj.setKey(hsKey);
	// set a default payload
	m_jwtObj.appendClaim("iss", "juangburgos");
	m_jwtObj.appendClaim("iat", static_cast<qint64>(QDateTime::currentDateTime().toTime_t()));
	m_jwtObj.appendClaim("exp", static_cast<qint64>(QDateTime::currentDateTime().addDays(7).toTime_t()));
	m_jwtObj.appendClaim("aud", "everybody");
	m_jwtObj.appendClaim("sub", "hey there");
	// set current value to views
	ui->plainTextClaims->setPlainText(m_jwtObj.getPayloadQStr());
	// setup combobox (exec at the end because it calls slot)
	ui->comboAlgorithm->addItems(QJsonWebToken::supportedAlgorithms());
#ifdef USE_QCA
	rsKey = QJsonWebKey::generateRSAPrivateKey(2048);
#endif // USE_QCA
}

Dialog::~Dialog()
{
	delete ui;
}

void Dialog::on_pushAddClaim_clicked()
{
	// get inputs and check them
	QString strClaimType = ui->lineClaimType->text();
	QString strValue     = ui->lineValue->text();
	if (strClaimType.isEmpty() || strValue.isEmpty())
	{
		return;
	}
	// set inputs to token
	m_jwtObj.appendClaim(strClaimType, strValue);
	// refresh view
	ui->plainTextClaims->setPlainText(m_jwtObj.getPayloadQStr());
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
	// clear on success
	ui->lineClaimType->clear();
	ui->lineValue->clear();
}

void Dialog::on_pushRemoveClaim_clicked()
{
	// get inputs and check them
	QString strClaimType = ui->lineClaimType->text();
	if (strClaimType.isEmpty())
	{
		return;
	}
	// set inputs to token
	m_jwtObj.removeClaim(strClaimType);
	// refresh view
	ui->plainTextClaims->setPlainText(m_jwtObj.getPayloadQStr());
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
	// clear on success
	ui->lineClaimType->clear();
	ui->lineValue->clear();
}

void Dialog::on_comboAlgorithm_currentIndexChanged(const QString &arg1)
{
	if (!arg1.startsWith(m_jwtObj.getAlgorithmStr().left(2)))
	{
		// change algorithm
		if (arg1.startsWith("HS"))
		{
			m_jwtObj.setKey(hsKey);
			ui->plainTextEditKey->blockSignals(true);
			ui->plainTextEditKey->setPlainText(QString::fromUtf8(hsKey->toJson()));
			ui->plainTextEditKey->blockSignals(false);
		}
#ifdef USE_QCA
		else if (arg1.startsWith("RS"))
		{
			if (rsKey.isNull())
			{
				rsKey = QJsonWebKey::generateRSAPrivateKey(2048);
			}
			m_jwtObj.setKey(rsKey);
			ui->plainTextEditKey->blockSignals(true);
			ui->plainTextEditKey->setPlainText(!rsKey.isNull() ? QString::fromUtf8(rsKey->toJson()) : QString());
			ui->plainTextEditKey->blockSignals(false);
		}
#endif // USE_QCA
	}
	// set new secret
	m_jwtObj.setAlgorithmStr(arg1);
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}

void Dialog::on_plainTextEditKey_textChanged()
{
	QString text = ui->plainTextEditKey->toPlainText();
	if (ui->comboAlgorithm->currentText().startsWith("HS"))
	{
		hsKey = QJsonWebKey::fromJsonWebKey(text.toUtf8());
		// set new secret
		m_jwtObj.setKey(hsKey);
	}
#ifdef USE_QCA
	else if (ui->comboAlgorithm->currentText().startsWith("RS"))
	{
		rsKey = QJsonWebKey::fromJsonWebKey(text.toUtf8());
		// set new secret
		m_jwtObj.setKey(rsKey);
	}
#endif // USE_QCA
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}

void Dialog::on_pushRandom_clicked()
{
	if (ui->comboAlgorithm->currentText().startsWith("HS"))
	{
		// set random secret
		int randLength = 10;
		QByteArray randAlphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		QByteArray secret;
		secret.resize(randLength);
		for (int i = 0; i < randLength; ++i)
		{
			secret[i] = randAlphanum.at(rand() % (randAlphanum.length() - 1));
		}
		hsKey = QJsonWebKey::fromOctet(secret);
		m_jwtObj.setKey(hsKey);
		// set random secret in lineedit
		ui->plainTextEditKey->blockSignals(true);
		ui->plainTextEditKey->setPlainText(QString::fromUtf8(hsKey->toJson()));
		ui->plainTextEditKey->blockSignals(false);
	}
#ifdef USE_QCA
	else if (ui->comboAlgorithm->currentText().startsWith("RS"))
	{
		rsKey = QJsonWebKey::generateRSAPrivateKey(2048);
		m_jwtObj.setKey(rsKey);
		// set random secret in lineedit
		ui->plainTextEditKey->blockSignals(true);
		ui->plainTextEditKey->setPlainText(!rsKey.isNull() ? QString::fromUtf8(rsKey->toJson()) : QString());
		ui->plainTextEditKey->blockSignals(false);
	}
#endif // USE_QCA
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}
