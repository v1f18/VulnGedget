package org.vulngedget.util;

import java.util.ArrayList;
import java.util.List;

public class AnnotationUtil {
    //使用在URL类上的注解，使用了该注解表示此类为URL类
    public static List<String> controllerClassAnnotaionDescList = new ArrayList(){{
            add("Lorg/springframework/web/bind/annotation/RequestMapping;");
            add("Lorg/springframework/web/bind/annotation/RestController;");
            add("Lorg/springframework/stereotype/Controller;");

        }};

    //使用在URL入口方法的注解，使用了该注解表示此方法为URL入口方法
    public static List<String> controllerMathodAnnotaionDescList = new ArrayList(){{
        add("Lorg/springframework/web/bind/annotation/RequestMapping;");
        add("Lorg/springframework/web/bind/annotation/GetMapping;");
        add("Lorg/springframework/web/bind/annotation/PostMapping;");
        add("Lorg/springframework/web/bind/annotation/PutMapping;");
        add("Lorg/springframework/web/bind/annotation/DeleteMapping;");
    }};


}
