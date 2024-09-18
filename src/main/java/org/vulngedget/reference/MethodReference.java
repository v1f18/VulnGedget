package org.vulngedget.reference;


import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class MethodReference {
    public String className;
    public String methodName;
    public String desc;
    public MethodParameterValue methodParameterValue;
    public MethodPathValueAnnotation methodPathValueAnnotation = new MethodPathValueAnnotation();
    public List<MethodReference> calledMethodList = new ArrayList<>();
    public boolean isControllerMethod;


    @Override
    public int hashCode() {
        int result = className != null ? className.hashCode() : 0;
        result = 31 * result + (methodName != null ? methodName.hashCode() : 0);

        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MethodReference handle = (MethodReference) o;

        if (className != null ? !className.equals(handle.className) : handle.className != null) return false;
        if (methodName != null ? !methodName.equals(handle.methodName) : handle.methodName != null) return false;
        return desc != null ? desc.equals(handle.desc) : handle.desc == null;
    }




}
