# Roxy
 一个Python客户端和PHP服务端的简单代理

某天正在想着用面板服务器做代理的屑意外的发现了[miniProxy](https://github.com/joshdick/miniProxy)这个神奇的PHP代理，但是鉴于它只能代理网站的流量所以就想自己做一个类似那种代理客户端的但是服务端可以完美契合PHP的。然后就诞生了这个货

因为众多的限制，这个货目前只能代理http流量并且慢的一匹，但是可以做到完美的http代理体验，支持cookie和各种header，可以顺利的完成登录等各种任务。

运行此代理需要本地有Python3并且安装了requirements里面的库，然后需要将自签证书安装到信任的根证书才能正常使用https，接下来需要一个php面板服务器，将index.php上传上去并且更改settings.ini，url改为你的面板服务器地址（注意有些面板服务器是不允许代理的一定要看清楚许可

自签证书的代码借鉴了GoAgent，是一个非常棒的代理，然鹅源作者已经停止更新，在此致敬！

[点击跳转安装步骤](install.md)

- [x] GET和POST
- [x] 其它的http协议
- [ ] 加密协议
- [ ] 图形客户端