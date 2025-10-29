## 🏷️ **Version Detection**
```
"Halo" intext:"2.21.0"
```

## 🔍 **Login Page Detection**

```
inurl:"/login" intext:"halo" title:"Login - halo"
```

```
inurl:"/console" intext:"halo-logo"
```

## 🔒 **Console/Admin Detection**

```
inurl:"/console" intext:"Halo" title:"Console"
```

```
inurl:"/console/setup" intext:"Initial setup"
```

## 🌐 **API Endpoint Discovery**

```
inurl:"/apis/api.storage.halo.run"
```
```
inurl:"/apis/console.api.halo.run"
```

```
inurl:"/apis/console.api.halo.run/v1alpha1/attachments"
```

## 🎯 **Specific Vulnerability Endpoints**

```
inurl:"/apis/console.api.halo.run/v1alpha1/attachments/-/upload-from-url"
```

```
inurl:"/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"
```
