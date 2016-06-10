#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>

namespace Ui {
class Dialog;
}

#include "../../src/qjsonwebtoken.h"

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

	QJsonWebToken m_jwtObj;

private slots:
    void on_pushAddClaim_clicked();

    void on_pushRemoveClaim_clicked();

    void on_lineSecret_returnPressed();

    void on_comboAlgorithm_activated(int index);

private:
    Ui::Dialog *ui;
};

#endif // DIALOG_H
