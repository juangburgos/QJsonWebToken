#include "dialog.h"
#include "ui_dialog.h"



Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
	// set some tooltips
	ui->pushRemoveClaim->setToolTip("To remove a claim you just need to define the <b>Claim Type<\b>");
	ui->pushRemoveClaim->setToolTipDuration(3500);
	// set a default payload
	m_jwtObj.appendClaim("iss", "aaa");
	m_jwtObj.appendClaim("iat", "bbb");
	m_jwtObj.appendClaim("exp", "ccc");
	m_jwtObj.appendClaim("aud", "ddd");
	m_jwtObj.appendClaim("sub", "eee");
	// set current value to views
	ui->plainTextClaims->setPlainText(m_jwtObj.getPayloadQStr());
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_pushAddClaim_clicked()
{
	// get inputs and check them

	// set inputs to token

	// refresh view

}

void Dialog::on_pushRemoveClaim_clicked()
{
	// get inputs and check them

	// set inputs to token

	// refresh view

}

void Dialog::on_lineSecret_returnPressed()
{

}

void Dialog::on_comboAlgorithm_activated(int index)
{

}
