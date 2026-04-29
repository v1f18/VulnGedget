package org;

public class classLoaderTest extends ClassLoader{
    public static void main(String[] args){
       new classLoaderTest().a();
    }

public void a(){
    System.out.println(this.getClass().getClassLoader());
}
}


