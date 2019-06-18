package com.kineticdata.bridgehub.adapter.footprints;

import com.kineticdata.bridgehub.adapter.QualificationParser;

public class FootprintsQualificationParser extends QualificationParser {
    public String encodeParameter(String name, String value) {
        return value;
    }
}
