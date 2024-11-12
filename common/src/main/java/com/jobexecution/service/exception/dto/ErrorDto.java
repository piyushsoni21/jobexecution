package com.jobexecution.service.exception.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorDto {
    @JsonProperty("reasonCode")
    private String reasonCode;

    @JsonProperty("description")
    private String description;

    @JsonProperty("details")
    private String details;
}