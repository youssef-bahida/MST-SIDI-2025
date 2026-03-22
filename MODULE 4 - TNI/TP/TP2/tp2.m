%=== Exercice 1 =====================================================
    % Calculer l'histogramme de l'image puis afficher l'image et son histogramme
          % image = imread("TP/TP2/cameraman.png");
          % histogramme = imhist(image);
          % subplot(1,2,1);imshow(image);title("Image de Camera Man");
          % subplot(1,2,2);bar(histogramme);title("Histogramme de l'image"); % la méthode bar est utilisée pour affciher les données stockées de vecteur Hitogramme(v1,v2,v3,........,vn)
    % Calculer l'histogramme l'égalisé de cette image, afficher
          % histEgal = histeq(image);
          % figure,bar(histEgal),title("Histogramme l'égalisé de l'image");
    % Etirer l'histogramme dans l'intervalle [0, 255]
          % imgEtir = imadjust(image);
          % figure,imshow(imgEtir),title("Image étirée");
    % Seuillage d'une image : selon l'histogramme choisir un seuil pour le seuillage de l'image
          % figure,bar(histogramme);
          % seuil = 90; % on essaye de séparer le personnage du fond
          % imgSeuil = image > 90;
          % figure,imshow(imgSeuil);title("Image Seuilée ( binaire)");
    % Effectuer le seuillage automatique de l'image par méthode d'Otsu. (Au sens d'Otsu, le seuil
          % OtsuSeuil = graythresh(image)*255;
          % imgOtsuSeuil = imbinarize(image);
          % figure,imshow(imgOtsuSeuil);
          % title(["Seuillage de l'image, Otsu valeur = " + num2str(OtsuSeuil)]);
        
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  
%=== Exercice 2 =====================================================

    % 1. Construire et annoter l'histogramme de l'image I.
	    % Initialisation de l'image 
		    % image = uint8(30*ones(64,64));
	    % 20x20 pixels et dont le 5ème ligne et 10eme colonne
		    % image(5:24,10:39) = 80 ;
	    % un rectangle d'intensité 120 de 35*20 pixels, lign = 35eme , colon = 25e
		    % image(35:54,25:59)  = 120;
	    % un rectangle d'intensité  200 de 10*5, dont 10e ligne et 50e colonne dans I,
		    % image(10:10+5-1,50:50+10-1) = 200;
	    % Affichage de l'image 
		    % subplot(2,2,1);
		    % imshow(image);
		    % title('Image Synthétique 64x64');
	    % Affichage de l'histogramme 
		    % histImg = imhist(image);
		    % subplot(2,2,2);
		    % bar(histImg);
		    % title("Histogramme de l'image");
    % 2. Quelle sera l'allure de l'histogramme suite à cette opération ? Justifiez votre réponse.
	    % l'allure de histogramme restera la même (invariante) , 
	    % car les transformations géométriques n'affectent pas l'histogramme.
    % 3. Application de bruit de type (salt and pepper) sur image originale, à probabilité de 0.2
		    % imgBruitSP = imnoise(image,"salt & pepper",0.2);
		    % subplot(2,2,3);
            % imhist(imgBruitSP);
            % title("Histogramme de Image Bruitée SP");
    
    % 4. Est-il possible de retrouver exactement l'image originale à 
    %    partir d'une simple modification de l'histogramme obtenu à la question 3 ? Justifier.
	    % Histogramme est une statistique globale, qui  ne contient pas , des informations sur 
	    % la position (x,y) des pixels , donc une modification comme (Égalisation) , 
	    % ne va pas restaurer image originale. 
    
    % 5. Quel serait le filtre spatial optimal à appliquer pour filtrer l'image bruitée ?
	    % le filtre médian taille 3x3 : car il consérve les conteurs , et élimine entièrement les implusions.
	    % imgFiltMedian = medfilt2(imgBruitSP,[3 3]);
	    % subplot(2,2,4);
	    % imshow(imgFiltMedian);
	    % title("Application de filter médian 3x3 sur image bruitée SP , p=20%");
    % 6. On rajoute à l'image originale un bruit de type sel et poivre de probabilité p=0.75. 
    % Quel serait le filtre spatial optimal à appliquer pour filtrer l'image bruitée ? 
	    % un filtre médian avec une fenêtre plus grande 5x5
    
    %7. Expliquer son fonctionnement.
	    % 1-Choisir une fenêtre (masque)
	    % 2-Collecter les valeurs de fenêtre
	    % 3-Trier les valeurs(min->max)
	    % 4-Prendre la médiane..
	    % 5-Remplacer le pixel central par valeur médiane.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 
%=== Exercice 3 =====================================================



% 1. Lecture ou création de l'image de test
	%img = imread('cameraman.png'); % Image standard de MATLAB
	%img = double(img) / 255; % Normalisation entre 0 et 1

% 2. Application des bruits successifs
	%imgBruitG = imnoise(img, 'gaussian');
	%imgBruitGM = imnoise(imgBruitG, 'salt & pepper', 0.15);

% --- FILTRAGE ---

	%filtrG = fspecial('gaussian', [5 5], 1);
		
	%imgfiltG = imfilter(imgBruitGM , filtrG ,'replicate');
	%imgfiltGM = medfilt2(imgfiltG , [5 5]);

	%imgfiltM  = medfilt2(imgBruitGM , [5 5]);
	%imgfiltMG = imfilter(imgfiltM, filtrG, 'replicate');

% --- AFFICHAGE ---

	%figure('Name', 'Comparaison des séquences de filtrage');


	%subplot(2,2,1);
	%imshow(imgBruitGM);
	%title('Image Bruitée (Gauss + S&P)');

	%subplot(2,2,2);
	%imshow(imgfiltGM);
	%title('Séquence A: Gaussien \rightarrow Médian');

	%subplot(2,2,3);
	%imshow(imgBruitGM);
	%title('Image Bruitée');

	%subplot(2,2,4);
	%imshow(imgfiltMG);
	%title('Séquence B: Médian \rightarrow Gaussien');


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 
%=== Exercice 4 =====================================================



    % 1. Chargement de l'image
    imgtest = imread('image_test.png');
    if size(imgtest, 3) > 1
        imgGray = rgb2gray(imgtest); 
    end
    imgtestNor = im2double(imgGray); 
    % --- DÉFINITION DES FILTRES ---
    % Filtre 1
    h1 = [-1 -1 -1; 0 0 0; 1 1 1];
    % Filtre 2
    h2 = (1/16) * [1 2 1; 2 4 2; 1 2 1];
    % Filtre 3
    h3 = (1/16) * [-1 -2 -1; -2 12 -2; -1 -2 -1];
    % Filtre 4 
    h4 = [-1 0 1; -1 0 1; -1 0 1];
    % Filtre 5 
    h5 = ones(35, 35) / (35^2); 
    % --- APPLICATION DES FILTRES ---
    res1 = imfilter(imgtestNor, h1, 'replicate');
    res2 = imfilter(imgtestNor, h2, 'replicate');
    res3 = imfilter(imgtestNor, h3, 'replicate');
    res4 = imfilter(imgtestNor, h4, 'replicate');
    res5 = imfilter(imgtestNor, h5, 'replicate');
    res6 = medfilt2(imgtestNor, [3 3]);
    % --- AFFICHAGE DES RÉSULTATS --
    figure('Name', 'Application des filtres');
    
    subplot(2,4,1); imshow(imgtest); title('Originale');
    subplot(2,4,2); imshow(res1); title('1. Filtre 1 ');
    subplot(2,4,3); imshow(res2); title('2. Filtre 2');
    subplot(2,4,4); imshow(res3, []); title('3. Filtre 3');
    subplot(2,4,5); imshow(res4); title('4. Filtre 4');
    subplot(2,4,6); imshow(res5); title('5. Filtre 5');
    subplot(2,4,7); imshow(res6); title('6. Filtre 6');
    
    







