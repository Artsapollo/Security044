package jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@ToString
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Address {

    @JsonProperty("line1")
    private String lineOne;

    @JsonProperty("line2")
    private String lineTwo;

    @JsonProperty("city")
    private String city;

    @JsonProperty("state")
    private String state;

    @JsonProperty("postalCode")
    private String postalCode;

    @JsonProperty("country")
    private String country;
}