package jwt.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@ToString
@JsonInclude
@EqualsAndHashCode
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenPayload {

    @JsonProperty("cardholderInformation")
    private CardholderInformation cardholderInformation;

    @JsonProperty("address")
    private Address address;

    @JsonProperty("expirationDate")
    private ExpirationDate expirationDate;

}