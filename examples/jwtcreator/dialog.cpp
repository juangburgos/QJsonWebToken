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
	m_jwtObj.appendClaim("iat", QString::number(QDateTime::currentDateTime().toTime_t()));
	m_jwtObj.appendClaim("exp", QString::number(QDateTime::currentDateTime().addDays(7).toTime_t()));
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
