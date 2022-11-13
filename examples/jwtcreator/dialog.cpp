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
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
	// set some tooltips
	ui->pushRemoveClaim->setToolTip("To remove a claim you just need to define the <b>Claim Type<\b>");
	ui->pushRemoveClaim->setToolTipDuration(3500);
	// set default secret
	ui->lineSecret->setText("mydirtysecret");
	m_jwtObj.setSecret("mydirtysecret");
	// set a default payload
	m_jwtObj.appendClaim("iss", "juangburgos");
    m_jwtObj.appendClaim("iat", QString::number(QDateTime::currentDateTime().toSecsSinceEpoch()));
    m_jwtObj.appendClaim("exp", QString::number(QDateTime::currentDateTime().addDays(7).toSecsSinceEpoch()));
	m_jwtObj.appendClaim("aud", "everybody");
	m_jwtObj.appendClaim("sub", "hey there");
	// set current value to views
	ui->plainTextClaims->setPlainText(m_jwtObj.getPayloadQStr());
	// setup combobox (exec at the end because it calls slot)
	ui->comboAlgorithm->addItems(QJsonWebToken::supportedAlgorithms());
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
	// set new secret
	m_jwtObj.setAlgorithmStr(arg1);
	// show new jwt
	ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}

void Dialog::on_lineSecret_textChanged(const QString &arg1)
{
	Q_UNUSED(arg1);
    // set new secret
    m_jwtObj.setSecret(ui->lineSecret->text());
    // show new jwt
    ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}

void Dialog::on_pushRandom_clicked()
{
    // set random secret
    m_jwtObj.setRandomSecret();
    // set random secret in lineedit
    ui->lineSecret->blockSignals(true);
    ui->lineSecret->setText(m_jwtObj.getSecret());
    ui->lineSecret->blockSignals(false);
    // show new jwt
    ui->plainTextSignedJwt->setPlainText(m_jwtObj.getToken());
}
