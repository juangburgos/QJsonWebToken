// The MIT License(MIT)
// Copyright(c) <2016> <Juan Gonzalez Burgos>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "dialog.h"
#include "ui_dialog.h"

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
	// setup initial button color
	ui->pushStatus->setStyleSheet("background-color: #ff8080; color: black; font: bold;");
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_plainTextEncoded_textChanged()
{
	QString strToken = ui->plainTextEncoded->toPlainText();
	// check validity
	QStringList listJwtParts = strToken.split(".");
	// check correct size
	if (listJwtParts.count() != 3)
	{
		// show error
		ui->plainTextHeader->setPlainText(QObject::trUtf8("ERROR : token must have the format xxxx.yyyyy.zzzzz"));
		ui->plainTextPayload->setPlainText(QObject::trUtf8("ERROR : token must have the format xxxx.yyyyy.zzzzz"));
		return;
	}
	QString strSecret = ui->lineEditSecret->text();
	if (strSecret.isEmpty())
	{
		// show error
		ui->plainTextHeader->setPlainText(QObject::trUtf8("ERROR : secret must be non-empty"));
		ui->plainTextPayload->setPlainText(QObject::trUtf8("ERROR : secret must be non-empty"));
		return;
	}
	// set token and secret
	QJsonWebToken token = QJsonWebToken::fromTokenAndSecret(strToken, strSecret);
	// get decoded header and payload
	QString strHeader = token.getHeaderQStr();
	QString strPayload = token.getPayloadQStr();
	ui->plainTextHeader->setPlainText(strHeader);
	ui->plainTextPayload->setPlainText(strPayload);
	// try to validate with secret
	if (token.isValid())
	{
		ui->pushStatus->setText(QObject::trUtf8("VALID"));
		ui->pushStatus->setStyleSheet("background-color: #1aff8c; color: black; font: bold;");
	} 
	else
	{
		ui->pushStatus->setText(QObject::trUtf8("INVALID"));
		ui->pushStatus->setStyleSheet("background-color: #ff8080; color: black; font: bold;");
	}

}

void Dialog::on_lineEditSecret_textChanged(const QString &arg1)
{
	on_plainTextEncoded_textChanged();
}
