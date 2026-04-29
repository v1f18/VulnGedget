package org;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping
public class testAnnotationMethod {

    @GetMapping("/source1")
    public void source(){
        add(11,1);
    }


    @GetMapping
    public int add(int a,int b){
        int c = a+b;
        return cut(c, b);
    }

    public int cut(int c,int d){
        int e = c-d;
        new test1().target(e);
        return e;
    }

}
class test1{
    public void target(int a){
        System.out.println(a);
    }
}