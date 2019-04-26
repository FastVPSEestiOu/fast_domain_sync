fast_domain_sync
================

* DEPRECATED, ONLY FOR COMPABILITY SUPPORT
* БОЛЕЕ НЕ ПОДДЕРЖИВАЕТСЯ, ОСТАВЛЕНО ДЛЯ СОВМЕСТИМОСТИ

Domain Sync plugin provides ability to use FASTDNS from ISPManager 4 Lite

Плагин позволяет синхронизировать изменения записей DNS сделанных в ISP Manager 4 Lite, установленных на серверах клиентов, с FASTDNS

Плагин написан на Python, при любом измении DNS у клиента оно исполняется и на центральном DNS сервере. Если неудача - откат.

При этом записи, которые уже созданые на центральном DNS и в панели управления ISPManager у пользователя (далее - просто "панели") начнут синхронизироваться автоматически. Записи, которые созданы на ISPManager и не существовали на центральном DNS до установки плагина - автоматичеcки не будут синхронизированы, их нужно вручную добавить на центральный DNS. DNS записи в панели ISPManager, которые были вновь созданы после установки плагина будут автоматичсеки добавлены на центральный DNS и все последующие изменения в них будут автоматичеcки отражаться на центральном DNS.

Установка:
* Нужно предварительно установить Питон на Debian, на CentOS он уже есть стандартно. apt-get install -y python
* Добавлена зависимость от python-requests. apt-get install -y python-requests
* Для работы плагина необходима функция "источники расширений". Ее наличие определяется следующим образом: Настройки сервера - Плагины и в верхнем левом углу должна быть белая кнопка "источники расширений". Если она есть, то уже стоит нужная версия панели и обновлять ее не нужно. В противном случае, если у панели нету поддержки источников расширений, то ее нужно обновлять до последней версии
* Идем в Настройки сервера -> Плагины -> Источники
* Посредством щелчка на зеленом плюсе добавляем новый репозиторий https://raw.githubusercontent.com/FastVPSEestiOu/fast_domain_sync/master/ispmgr_plugins.xml
* Идем в Настройки сервера -> Плагины
* Устанавливаем плагин domainsync - подтвердить 
* Перегружаем страницу (ОБЯЗАТЕЛЬНО!!!) по F5 (Windows, Linux) или Cmd+R (MacOS)
* Выбираем Инструменты > Синхронизация DNS
* Прописываем токен для доступа к центральному DNS аккаунту
* Тыцаем на Ok если коннект успешный, окошко закроется само.

Как обновить на новую версию
* Идем в "Настройки сервера -> Плагины".
* На строке domainssync должно быть примерно следующее: domainssync (Требуется Python >= 2.5 (не Python3)) 0.5 Michael Neradkov / FastVPS. Это означает, что панель увидела обновление и может его выполнить.
* Щелкаем на панели сверху кнопку с красным прямоугольником и зеленой стрелкой.
* Идем в меню "Настройки сервера - Синхронизация DNS" и указываем токен для FASTDNS.
* Наслаждаемся новой версией! (smile)

Описание конфига /usr/local/ispmgr/etc/domainssync.ini
```bash
[fastdns]
token = xxx
 
[log]
; 1 - минимум информации, 9 - максимум
level = 1
```

Известные ограничения:
* Событие на добавление домена в панель срабатывает только из раздела "Доменные имена". Из раздела WWW-домены оно не реагирует.
