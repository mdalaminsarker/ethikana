<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateImagesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('images', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('pid')->unsigned();
            $table->integer('user_id')->unsigned();
            $table->string('imageGetHash');
            $table->text('imageTitle')->nullable();
            $table->string('imageRemoveHash');
            $table->string('imageLink');
            $table->tinyInteger('isShowable')->default(1);
            $table->string('relatedTo');
            $table->foreign('pid')->references('id')->on('places')->onDelete('cascade');  
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('images');
    }
}
