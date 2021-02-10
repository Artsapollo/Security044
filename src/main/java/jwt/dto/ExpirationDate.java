package jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString
@NoArgsConstructor
public class ExpirationDate {

    @JsonProperty("month")
    private String month;

    @JsonProperty("year")
    private String year;
}
