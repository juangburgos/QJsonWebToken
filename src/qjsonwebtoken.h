#ifndef QJSONWEBTOKEN_H
#define QJSONWEBTOKEN_H

#include <QObject>

class QJsonWebToken : public QObject
{
    Q_OBJECT
public:
    explicit QJsonWebToken(QObject *parent = 0);

signals:

public slots:
};

#endif // QJSONWEBTOKEN_H