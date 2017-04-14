<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Token extends Model
{
    //assign the table 
    protected $table = "tokens";
    protected $fillable =[
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
