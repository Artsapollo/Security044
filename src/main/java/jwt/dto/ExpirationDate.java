package jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@ToString
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class ExpirationDate {

    @JsonProperty("month")
    private String month;

    @JsonProperty("year")
    private String year;
}
