package org.vulngedget.reference;

import lombok.Data;

@Data
public class FieldReference {
    public String fieldName;
    public String fieldDesc;

    public FieldReference(String fieldName, String fieldDesc) {
        this.fieldName = fieldName;
        this.fieldDesc = fieldDesc;
    }
}
