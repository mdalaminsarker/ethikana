<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class BookARide extends Model
{
    //
    public function passenger(){
    	return $this->belongsTo('App\User','user_id');
    }
}
