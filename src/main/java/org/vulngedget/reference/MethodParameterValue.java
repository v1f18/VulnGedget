package org.vulngedget.reference;

import java.util.ArrayList;
import java.util.List;

public class MethodParameterValue {
    public String methodName;
    public List<String> parameterList = new ArrayList<>();
    public String className;

    /**
     * if true, is a request parameter
     */
    public boolean isRequestParameter;

    public boolean isPathParameter;


}
