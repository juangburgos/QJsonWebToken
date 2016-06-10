#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private slots:
    void on_plainTextEncoded_textChanged();

    void on_lineEditSecret_textChanged(const QString &arg1);

private:
    Ui::Dialog *ui;
};

#endif // DIALOG_H
