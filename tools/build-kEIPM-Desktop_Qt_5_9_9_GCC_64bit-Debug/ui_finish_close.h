/********************************************************************************
** Form generated from reading UI file 'finish_close.ui'
**
** Created by: Qt User Interface Compiler version 5.9.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FINISH_CLOSE_H
#define UI_FINISH_CLOSE_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Finish_Close
{
public:
    QVBoxLayout *verticalLayout;
    QGroupBox *Finish_Box;
    QHBoxLayout *horizontalLayout;
    QTextBrowser *text_remind;
    QWidget *widget;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *Btn_Finish;

    void setupUi(QDialog *Finish_Close)
    {
        if (Finish_Close->objectName().isEmpty())
            Finish_Close->setObjectName(QStringLiteral("Finish_Close"));
        Finish_Close->resize(337, 256);
        verticalLayout = new QVBoxLayout(Finish_Close);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        Finish_Box = new QGroupBox(Finish_Close);
        Finish_Box->setObjectName(QStringLiteral("Finish_Box"));
        horizontalLayout = new QHBoxLayout(Finish_Box);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        text_remind = new QTextBrowser(Finish_Box);
        text_remind->setObjectName(QStringLiteral("text_remind"));

        horizontalLayout->addWidget(text_remind);


        verticalLayout->addWidget(Finish_Box);

        widget = new QWidget(Finish_Close);
        widget->setObjectName(QStringLiteral("widget"));
        horizontalLayout_2 = new QHBoxLayout(widget);
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        Btn_Finish = new QPushButton(widget);
        Btn_Finish->setObjectName(QStringLiteral("Btn_Finish"));

        horizontalLayout_2->addWidget(Btn_Finish);


        verticalLayout->addWidget(widget);


        retranslateUi(Finish_Close);

        QMetaObject::connectSlotsByName(Finish_Close);
    } // setupUi

    void retranslateUi(QDialog *Finish_Close)
    {
        Finish_Close->setWindowTitle(QApplication::translate("Finish_Close", "Dialog", Q_NULLPTR));
        Finish_Box->setTitle(QApplication::translate("Finish_Close", "\346\217\220\347\244\272\357\274\232", Q_NULLPTR));
        Btn_Finish->setText(QApplication::translate("Finish_Close", "\345\256\214\346\210\220", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class Finish_Close: public Ui_Finish_Close {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_FINISH_CLOSE_H
