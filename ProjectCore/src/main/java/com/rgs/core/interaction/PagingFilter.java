package com.rgs.core.interaction;

import lombok.Data;

import java.io.Serializable;

@Data
public class PagingFilter implements Serializable{

    private String field;
    private String op;
    private String term;
}