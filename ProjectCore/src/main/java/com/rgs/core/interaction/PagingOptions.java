package com.rgs.core.interaction;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

@Data
public class PagingOptions implements Serializable{

    private Integer pageIndex;
    private Integer pageSize;
    private List<PagingSort> sorts;
    private List<PagingFilter> filters;

}