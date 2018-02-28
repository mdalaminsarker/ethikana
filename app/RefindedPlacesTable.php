<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class RefindedPlacesTable extends Model {

    protected $fillable = [
      'longitude'
      'latitude',
      'address', // Contains address, area, city postcode
      'type'
      'subtype',
      'ucode'
      'Email',
      'number',
      'seconday_number'
      'website',

    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships

}
