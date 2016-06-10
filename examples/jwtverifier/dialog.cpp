#include "dialog.h"
#include "ui_dialog.h"

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
	// setup initial button color
	ui->pushStatus->setStyleSheet("background-color: #ff8080; color: black; font: bold;");
	//ui->pushStatus->setStyleSheet("background-color: #1aff8c; color: black; font: bold;");
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_plainTextEncoded_textChanged()
{

}

void Dialog::on_lineEditSecret_textChanged(const QString &arg1)
{

}
