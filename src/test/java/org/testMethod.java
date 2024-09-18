package org;

import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping
public class testMethod {

    public void source(){
        add(11,1);
    }


    public int add(int a,int b){
        int c = a+b;
        return cut(c, b);
    }

    public int cut(int c,int d){
        int e = c-d;
        new test().target(e);
        return e;
    }
}

class test{
    public void target(int a){
        System.out.println(a);
    }
}