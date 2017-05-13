<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Image extends Model
{
    //
    protected $table = "images";
    protected $fillable =[
      'pid',
      'user_id',
      'imageGetHash',
      'imageTitle',
      'imageRemoveHash',
      'imageLink',
      'isShowable'
    ];

    public function places()
    {
        return $this->belongsTo('App\Place','pid');
    }
}
