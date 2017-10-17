<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class BusinessDetails extends Model
{
    //
    protected $table = "business_details";
    protected $primaryKey="id";
    protected $fillable =[
    	'business_uid',
    	'business_description',
    ];
}
