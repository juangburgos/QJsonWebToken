#include "dialog.h"
#include "ui_dialog.h"

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_pushAddClaim_clicked()
{

}

void Dialog::on_pushRemoveClaim_clicked()
{

}

void Dialog::on_lineSecret_returnPressed()
{

}

void Dialog::on_comboAlgorithm_activated(int index)
{

}
