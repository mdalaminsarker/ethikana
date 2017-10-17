<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Offer extends Model
{
    //
    protected $table='offers';
    protected $fillable = [
        'pid',
        'offer_title',
	    'offer_description',
    ];

    public function offerForPlace(){
    	$this->belongsTo('App\Place','pid');
    }

}
