package org.vulngedget.util;

import java.util.ArrayList;
import java.util.List;

public class AnnotationUtil {
    public static List<String> controllerClassAnnotaionDescList = new ArrayList(){{
            add("Lorg/springframework/web/bind/annotation/RequestMapping;");
            add("Lorg/springframework/web/bind/annotation/RestController;");
            add("Lorg/springframework/stereotype/Controller;");

        }};

    public static List<String> controllerMathodAnnotaionDescList = new ArrayList(){{
        add("Lorg/springframework/web/bind/annotation/RequestMapping;");
        add("Lorg/springframework/web/bind/annotation/GetMapping;");
        add("Lorg/springframework/web/bind/annotation/PostMapping;");
        add("Lorg/springframework/web/bind/annotation/PutMapping;");
        add("Lorg/springframework/web/bind/annotation/DeleteMapping;");
    }};


}
