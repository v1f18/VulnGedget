package org.vulngedget.reference;

import java.util.ArrayList;
import java.util.List;

public class InvocationDetail {
    public String callerClassName;
    public String callerMethodName;
    public String callerDesc;
    public String calleeClassName;
    public String calleeMethodName;
    public String calleeDesc;
    public String receiver;
    public int lineNumber = -1;
    public int candidateCount = 1;
    public List<String> arguments = new ArrayList<>();
}
