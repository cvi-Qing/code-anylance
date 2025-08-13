# hw  n day 复现

根据情报的poc ，/manage/intercom/为绕过的信息查看代码，可以分析出来/manage/intercom/为绕过的信息，

![image-20250813164948851](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20250813164948851.png)

## 鉴权绕过

通过查看代码

![image-20250813155435436](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20250813155435436.png)

此处为拦截器，path 表示请求（`/**`）进行拦截 通过跟进代码UserHandlerInterceptor

````java
 <!-- SpringMVC拦截器 -->
    <mvc:interceptors>
        <mvc:interceptor>
            <mvc:mapping path="/**"/>
            <bean class="com.hanvon.iface.web.filter.UserHandlerInterceptor"></bean>
        </mvc:interceptor>
    </mvc:interceptors>
</beans>
````

![image-20250813160207090](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20250813160207090.png)

根据代码来看

![image-20250813161914909](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20250813161914909.png)

````java
            if (!this.isWhiteUri(uri)) {
                if (session.getAttribute("__sessional_user__") == null) {
                    String token = request.getParameter("globalToken");
                    if (!Utils.isEmpty(token)) {
                        String s = Utils.decrypt(token);
                        String[] arr = s.split(",");
                        if (arr.length == 6 && arr[2].matches("\\d+") && arr[3].matches("\\d+")) {
                            String ip = arr[1];
                            Long time = Long.parseLong(arr[2]) + 1483200000000L;
                            long curr = System.currentTimeMillis();
                            if (Math.abs(time - curr) < 1800000L) {
                                SessionalUser su = new SessionalUser();
                                su.setId(Long.parseLong(arr[3]));
                                su.setUserName(Utils.decrypt(arr[4]));
                                su.setRealName(Utils.decrypt(arr[5]));
                                TheApp.setCurrentUser(su);
                                session.setAttribute("__sessional_user__", su);
                            }
                        }
                    }
````

代码中的isWhiteUri(uri) 存在及安全问题，这段代码表示只要是url包含白名单内容均通过放行，所以上述白名单列表均存在未授权

## 文件上传漏洞

通过上方的未授权漏洞，还有payload，能判断出一些信息，直接定位代码，这里可以看到没有进行任何的一个过滤，直接进行了上传，并且上传到了resource文件夹下

````java
  public RequestJson uploadMapFile(HttpServletRequest request) {
        RequestJson result = new RequestJson();
        try {
            String fileName = null;
            String fileType = null;
            if (!ServletFileUpload.isMultipartContent(request)) {
                result = RequestJson.failuerResult(result, "网络错误！");
                return result;
            }
            MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;
            Map
 fileMap = multipartRequest.getFileMap();
            String uploadPath = null;
            for(Map.Entry
 entity : fileMap.entrySet()) {
                MultipartFile mf = (MultipartFile)entity.getValue();
                if (!mf.isEmpty()) {
                    String fileTypeStr = mf.getOriginalFilename();
                    String fileId = UUID.randomUUID().toString().replace("-", "");
                    fileName = fileTypeStr.split("\\.")[0];
                    fileType = fileTypeStr.split("\\.")[1];
                    String path = request.getSession().getServletContext().getRealPath("/resource");
                    File tmpFile = new File(path);
                    if (!tmpFile.exists()) {
                        tmpFile.mkdir();
                    }
                    uploadPath = path + "\\" + fileId + "." + fileType;
                    File targetFile = new File(uploadPath);
                    Files.copy(mf.getInputStream(), targetFile.toPath(), new CopyOption[]{StandardCopyOption.REPLACE_EXISTING});
                    uploadPath = fileId + "." + fileType;
                    fileName = fileName + "." + fileType;
                }
            }
            Map
 map = new HashMap();
            map.put("fileName", fileName);
            map.put("fileType", fileType);
            map.put("path", uploadPath);
            result = RequestJson.successResult(result, map, "上传成功！");
        } catch (Exception e) {
            String msg = getMessage("basics_go_wrong") + e.getLocalizedMessage();
            result = RequestJson.errorResult(result, msg);
            e.printStackTrace();
        }
        return result;
    }
````

