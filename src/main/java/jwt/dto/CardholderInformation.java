package jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@ToString
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class CardholderInformation {

    @JsonProperty("primaryAccountNumber")
    private String primaryAccountNumber;

    @JsonProperty("cvv2")
    private String cvv2;

    @JsonProperty("name")
    private String name;

    @JsonProperty("expirationDate")
    private ExpirationDate expirationDate;

    @JsonProperty("billingAddress")
    private Address billingAddress;

    @JsonProperty("highValueCustomer")
    private Boolean highValueCustomer;

    @JsonProperty("riskAssessmentScore")
    private String riskAssessmentScore;
}
