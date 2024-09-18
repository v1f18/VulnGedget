package org;

import lombok.Data;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping({"/a"})
public class testAnnotation {



    @RequestMapping(path = "/path1",value = "/value1")
    public void test1(){
        System.out.println("");
    }

    @RequestMapping("/b/{id}/c")
    public void test2(@PathVariable String id,@PathVariable String id2,@PathVariable String id3){
        System.out.println(id);
    }


}
