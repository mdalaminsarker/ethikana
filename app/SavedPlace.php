<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class SavedPlace extends Model
{
    //
    protected $table = "saved_places";
    protected $fillable =[
      'uCode',
      'device_ID',
      'email',

    ];
}

